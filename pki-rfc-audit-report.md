# NCANode — RFC-Compliance Audit Report

**Repository:** `/Users/zhek/IdeaProjects/NCANode` (branch `v4`)
**Scope:** PKI signature/verification surface — CMS/CAdES, XML-DSig, WSSE, PAdES/PDF, OCSP, CRL, TSP/timestamp, certificate path & extension processing.
**Result:** 12 confirmed findings (5 high, 2 medium, 5 low). 23 raw findings refuted on adversarial verification.

This is a focused, not a sprawling, defect set. The cryptographic core is sound — signature and digest checks correctly delegate to Kalkan/BouncyCastle/Santuario, and per-signature cert binding (WSSE/CMS) is done carefully. Every confirmed high-severity issue lives at one layer: the **verification contract** — the gap between "the math checks out" and "this document was validly signed." The structural root cause is that `VerificationResponse` exposes only a blanket `valid` flag plus signer identities, never *what was actually covered*, so the service silently makes the "what was signed" decision for the caller — and in several flows gets it wrong.

---

## CRITICAL
None.

---

## HIGH

### H-1. CMS with zero SignerInfos is reported `valid=true`
- **RFC:** RFC 5652 §5.1 / §5.6 (SignedData must carry signers; verification is a per-signer assertion)
- **Where:** `src/main/kotlin/kz/ncanode/service/CmsService.kt:242`, `:245`, `:318`
- **What's wrong:** `var valid = true` is set before the per-signer loop. If `cms.signerInfos.signers` is empty, the loop at line 245 never executes, `signer.verify` (line 306) is never called, and line 318 returns `CmsVerificationResponse(valid = true, signers = [])`. `SignerInfos ::= SET OF SignerInfo` permits an empty SET; BouncyCastle returns an empty store rather than throwing, so the structure parses and reaches the loop. No upstream guard exists (controller does presence-only `@Valid`).
- **Why it matters:** An attacker wraps arbitrary content in a SignedData with no SignerInfos and presents it as "verified." Any client keying an authorization decision on the top-level `valid` flag without separately asserting `signers` is non-empty treats an unsigned blob as a valid signature.
- **Fix:** Add an empty-signers guard before the loop returning `valid=false` — mirroring `XmlService.verify`'s existing `valid = initial > 0` guard (`XmlService.kt:143`).

### H-2. CMS signer whose certificate is absent from the embedded store is silently accepted (signature never checked)
- **RFC:** RFC 5652 §5.6
- **Where:** `src/main/kotlin/kz/ncanode/service/CmsService.kt:300-313`, `:315`
- **What's wrong:** `certs = certStore.getCertificates(s.sid)`. The signature check `signer.verify(...)` and `cert.isValid(...)` run **only** inside `for (cert in certs)` (lines 300-313). If that collection is empty — standard `CertStore` behavior when the signer cert is omitted from `SignedData.certificates` or the `issuerAndSerialNumber`/SKI doesn't match — the loop body never runs, `valid` stays `true` (initialised line 242), and line 315 records `CmsSignerInfo(certificates = [], tsp = ...)` as success. `valid` is a single AND-accumulator over all signers, so an appended cert-less SignerInfo contributes no failure.
- **Why it matters:** Detached/external-cert workflows (where certs are commonly not embedded) report `valid=true` without ever verifying the signature. An attacker appends a SignerInfo with no matching certificate and the whole CMS still returns valid.
- **Fix:** Track per-signer verification explicitly: a `signerVerified` flag set true only when both `signer.verify` and `cert.isValid` pass; after the loop, set `valid=false` if `certs.isEmpty()` or `!signerVerified`. For legitimate external-cert flows, require the caller to supply the signer certificate.

### H-3. XML-DSig verify never confirms the signed Reference covers the document (XML Signature Wrapping)
- **RFC:** W3C xmldsig-core 2nd Ed. §3.2.2 (Reference Validation) + security note §8.1.3
- **Where:** `src/main/kotlin/kz/ncanode/service/XmlService.kt:138-178`, `src/main/kotlin/kz/ncanode/wrapper/XMLSignatureWrapper.kt:65-70`
- **What's wrong:** `verify()` locates each `<ds:Signature>` and calls `checkSignatureValue(cert)`. Santuario *does* validate SignedInfo and every Reference digest (verified against the xmlsec-4.0.3 bytecode — this is **not** a skipped-digest bug). But nothing inspects the Reference URI/Transforms or asserts the Reference targets the document root / application payload. Whatever the signature references (an enveloped `#fragment`, a relocated/wrapped element) is accepted, and `verify()` returns `valid=true`.
- **Why it matters:** Classic XML Signature Wrapping. An attacker who holds any document legitimately signed by holder H relocates H's signed element into an inert position and injects attacker-controlled content as the apparent body; the still-present signed fragment's digest matches, `checkSignatureValue` passes, and NCANode reports `valid=true` with H as signer. A consumer reading the body content is misled about what H signed — and the API gives no signal about what was actually covered.
- **Fix:** After `checkSignatureValue`, enumerate SignedInfo References and assert one resolves to the document root / payload (matching the empty-URI whole-document reference the signing side emits at `DocumentWrapper.kt:40`); reject coverage-relocating Transforms. Better: return the actually-signed octets so the consumer trusts only demonstrably-covered content.

### H-4. PDF verify never checks the signature `/ByteRange` covers the whole document (PAdES incremental-update forgery)
- **RFC:** ETSI EN 319 142-1 (PAdES) / ISO 32000-1 §12.8.1 (last signature must cover the entire document)
- **Where:** `src/main/kotlin/kz/ncanode/service/PdfService.kt:174-266`
- **What's wrong:** `verifySignature()` verifies the CMS over exactly the bytes returned by `signature.getSignedContent(originalPdfBytes)` (line 186). PDFBox's `getSignedContent` only extracts the bytes the `/ByteRange` points at — it does **not** validate that the range spans the whole file. The code never reads `getByteRange()`, never compares its end against EOF, and never detects content appended after the signed revision. The loop (lines 156-160) iterates each signature dictionary independently with no "last signature covers the document" rule.
- **Why it matters:** Take a validly signed PDF, append an incremental update (new page, overlaid annotation, changed form field) after the signed revision. The original signature still verifies over its ByteRange, so NCANode reports `valid=true` while the rendered document differs from what was signed — the standard PAdES appended-content forgery.
- **Fix:** Read `PDSignature.getByteRange()`, assert it spans offset 0 to EOF with only the `/Contents` hole (`range[0]==0` and `range[2]+range[3]==fileLength`), detect incremental updates after the signed revision, and require the last signature to cover the whole document. Otherwise mark the signature as not whole-document-covering.

---

## MEDIUM

### M-1. WSSE verify does not assert the signature covers the SOAP Body
- **RFC:** OASIS WS-Security X.509 Token Profile 1.1 §3.1 / SOAP Message Security 1.1 §8
- **Where:** `src/main/kotlin/kz/ncanode/service/WsseService.kt:168-193`
- **What's wrong:** For each `ds:Signature` the code correctly resolves the cert from the signature's **own** `SecurityTokenReference` (avoiding cert/sig confusion — a genuine strength) and calls `checkSignatureValue(cert.publicKey)`. But it never enumerates the signature's References nor asserts any resolves to `soapenv:Body`, and never explicitly registers `wsu:Id` as an ID attribute.
- **Why it matters:** WS-Security XSW. Santuario's `secureValidation` (enabled by the `XMLSignature(Element, String)` constructor at line 170) blocks the *duplicate-id* copy-paste variant, but **not** the move-original/unique-id variant: keep the single original signed element (referenced by its Id) in a benign header location and substitute a malicious Body with a different Id. `checkSignatureValue` still verifies the surviving element's digest, so `verify()` returns `valid=true` while the Body the downstream service acts on was never signed.
- **Severity note:** Corrected to **medium** (down from the raw high): the simplest XSW variant is library-mitigated; only the move-original variant survives.
- **Fix:** After `checkSignatureValue`, enumerate References and assert one resolves to `soapenv:Body` (plus any other consumed elements); register `wsu:Id` explicitly before resolution.

### M-2. Delegated OCSP responder certificate validity/revocation is not verified
- **RFC:** RFC 6960 §4.2.2.2 (authorized responders) / §4.2.2.2.1 (revocation checking of an authorized responder)
- **Where:** `src/main/kotlin/kz/ncanode/service/OcspService.kt:242-273`
- **What's wrong:** `findVerifiedResponderCertificate` verifies the embedded responder cert's signature chains to the issuer (line 255) and that it carries `id-kp-OCSPSigning` EKU (lines 262-267), but never calls `checkValidity()`/compares notBefore/notAfter, never checks whether the responder cert itself is revoked, and never inspects `id-pkix-ocsp-nocheck` (1.3.6.1.5.5.7.48.1.5). `BasicOCSPResp.getProducedAt()` is unused.
- **Why it matters:** An expired delegated responder cert, or one whose key has been revoked after compromise, is still trusted. An attacker who compromises a once-valid delegated OCSP-signing key can forge "good" responses for arbitrary revoked certs indefinitely.
- **Severity note:** Medium, not high — requires compromise/expiry of a CA-issued OCSP-signing cert, and NCA's primary path is the CA-signs-directly branch (line 231). Still a real §4.2.2.2.1 omission.
- **Fix:** After the chain+EKU checks, call `respCert.checkValidity(brep.producedAt)`; check `id-pkix-ocsp-nocheck` and, if absent, perform a revocation check on the responder cert; if present, honor the CA's waiver.

---

## LOW

These are genuine conformance defects with **no current exploit** against NCA's purpose-built PKI. They cluster around one omission: there is no JDK `CertPathValidator`/PKIXParameters engine anywhere in the codebase (grep for `CertPathValidator`/`PKIXParameters`/`CertPathBuilder`/`TrustAnchor`/`getCriticalExtensionOIDs` returns nothing in `src/main`). Adopting the JDK PKIX path would resolve L-1 through L-4 in one stroke.

### L-1. RFC 5280 §6 path validation not implemented; chain stops at the immediate (operator-pinned) issuer
- **RFC:** RFC 5280 §6.1 / §6.1.3
- **Where:** `src/main/kotlin/kz/ncanode/wrapper/CertificateWrapper.kt:155-168`, `src/main/kotlin/kz/ncanode/service/CaService.kt:163-168`
- **What's wrong:** `isValid()` checks only leaf date validity, that `issuerCertificate` is non-null, the immediate issuer's date validity, and leaf OCSP/CRL. `getRootCertificateFor` matches the first bundle cert whose subjectDN == leaf issuerDN and whose key verifies the leaf signature — for NCA certs that's the **intermediate** CA, not the self-signed root. The intermediate's chain to the root is never built, and `pathLenConstraint`/`basicConstraints` CA:TRUE/`nameConstraints` are never enforced across a multi-level chain.
- **Severity note:** Corrected to **low** (raw finding overstated impact). `getRootCertificateFor` requires `cert.verify(root.publicKey)` against operator-pinned bundle certs, so an attacker **cannot** inject an unknown intermediate — forging requires a bundle cert's private key, the same trust boundary a full path build would impose. The residual gap is missing *constraint processing*, not unvalidated trust. (NCA intermediates function as deliberately operator-pinned trust anchors, which §6.1 permits.)
- **Fix:** Route the trust decision through `CertPathValidator`/`PKIXParameters` with the CA bundle as `TrustAnchor`s, or at minimum process basicConstraints/pathLen/nameConstraints across the chain.

### L-2. Intermediate/issuer CA revocation not checked during per-request verification
- **RFC:** RFC 5280 §6.1.3(a)(2)/(a)(3)
- **Where:** `src/main/kotlin/kz/ncanode/wrapper/CertificateWrapper.kt:155-168`, `src/main/kotlin/kz/ncanode/service/CertificateService.kt:57-65`
- **What's wrong:** `isValid()` runs OCSP/CRL only for the leaf; for the issuer it checks only `issuer.isDateValid(date)` (line 158). `attachValidationData` sets `ocspStatus`/`crlStatus` on the leaf only.
- **Why it matters:** A revoked-but-not-yet-expired intermediate would still validate leaf signatures. The only issuer-revocation mechanism is `CaService.updateCache` Pass 2 — CRL-only, up to ~24h stale, decoupled from the per-request validation `date`, and it re-downloads rather than ejects a revoked CA.
- **Fix:** Check OCSP/CRL on `issuerCertificate` at the same validation `date`; populate its `ocspStatus`/`crlStatus`. The JDK PKIX path with `PKIXRevocationChecker` covers this.

### L-3. Unrecognized critical CRL extensions are not rejected
- **RFC:** RFC 5280 §5.2 / §5.1.1.1
- **Where:** `src/main/kotlin/kz/ncanode/service/CrlService.kt:240-305`, `:458-471`
- **What's wrong:** `loadCrl`/`verify` call `crl.isRevoked()` directly and never inspect `getCriticalExtensionOIDs()` (no IDP/onlyContains* scoping either). Because it bypasses `CertPathValidator`/`PKIXRevocationChecker`, the JDK does not enforce the MUST-NOT-use-unrecognized-critical-extension rule on this path.
- **Why it matters:** A CA could mark a scope-narrowing extension critical so non-conforming relying parties ignore it; this service would reach a false ACTIVE. A REVOKED listing still yields REVOKED (safe). Not exploitable against current NCA CRLs (non-critical extensions only).
- **Fix:** Reject CRLs with unsupported critical extensions; implement IDP scoping; or validate through the JDK revocation checker.

### L-4. Unrecognized critical extensions in end-entity/signing certs are silently ignored
- **RFC:** RFC 5280 §4.2 (MUST reject a cert with an unrecognized critical extension)
- **Where:** `src/main/kotlin/kz/ncanode/wrapper/CertificateWrapper.kt:155-168`, `src/main/kotlin/kz/ncanode/service/CertificateService.kt:299-353`
- **What's wrong:** No path calls `getCriticalExtensionOIDs()`/`hasUnsupportedCriticalExtension()`. A cert is accepted as long as the signature verifies and revocation passes; a critical `policyConstraints`/`nameConstraints`/`keyUsage` the service doesn't process is treated as absent.
- **Why it matters:** A constrained cert can be honored outside its issuer-stated constraints. Largely mitigated for the trust decision by fixed-bundle chaining, but the §4.2 MUST is unmet.
- **Fix:** Call `hasUnsupportedCriticalExtension()` in `isValid` and reject; or use the JDK PKIX validator (auto-rejects unknown critical extensions).

### L-5. TSA EKU `id-kp-timeStamping` checked for presence only, not criticality or sole-EKU
- **RFC:** RFC 3161 §2.3 (id-kp-timeStamping MUST be present, the ONLY EKU, and the extension MUST be critical)
- **Where:** `src/main/kotlin/kz/ncanode/service/TspService.kt:153-158`
- **What's wrong:** `verify()` checks only membership (`if (EKU_TIME_STAMPING_OID !in eku) return null`). It does not check that the EKU extension is critical or that timestamping is the sole EKU. The verify path deliberately replaced Kalkan's `TSPUtil.validateCertificate()` (to skip `checkValidity()` for archival/CAdES-T timestamps) but dropped these two checks; `info()` still calls the strict `validate()` but `info()` is diagnostic, not security-gating.
- **Why it matters:** A multi-purpose cert that merely also lists timestamping, or one with a non-critical EKU, would be accepted as a TSA. NCA production TSA certs satisfy both; the risk is non-conformant third-party tokens.
- **Fix:** Assert `extendedKeyUsage.size == 1` and that `2.5.29.37` is in `getCriticalExtensionOIDs()`, mirroring the create-path's `validate()`.

### L-6. `fromKeyUsageBits()` NPEs on a certificate that legally omits keyUsage
- **RFC:** RFC 5280 §4.2.1.3 (keyUsage is OPTIONAL)
- **Where:** `src/main/kotlin/kz/ncanode/wrapper/CertificateWrapper.kt:75`, `src/main/kotlin/kz/ncanode/dto/certificate/CertificateKeyUsage.kt:10-14`
- **What's wrong:** `toCertificateInfo()` calls `CertificateKeyUsage.fromKeyUsageBits(cert.keyUsage)`. `X509Certificate.getKeyUsage()` returns `null` when the extension is absent (Kotlin platform type `BooleanArray!`), and `fromKeyUsageBits` indexes `keyUsageBits[0]` with no null guard → NPE. The single/info verify methods catch `CertificateException`/`IOException`/`SignatureException`/etc. but **not** `NullPointerException`, so it propagates as a 500/ServerException.
- **Why it matters:** Robustness/DoS on a fully RFC-legal attacker-supplied cert (reachable from CMS/XML/x509-info/verify/PDF/WSSE flows). Not a bypass.
- **Fix:** Make `fromKeyUsageBits` accept `BooleanArray?` and return an empty/all-false value (or null) when the argument is null.

---

## What was checked but found compliant

No component passed *entirely* clean on first pass, but several behaviors were specifically examined and verified correct, and 23 raw findings were refuted on verification:

- **Cryptographic signature & digest validation** delegates correctly to Kalkan/BouncyCastle (`CMSSignedData`, `SignerInformation.verify`) and Santuario (`XMLSignature.checkSignatureValue` — confirmed against xmlsec-4.0.3 bytecode to validate both SignedInfo and every Reference digest, *not* a stub).
- **Per-signature certificate binding (WSSE/CMS)** is done right: each signature resolves its cert from its own `SecurityTokenReference`/`SignerIdentifier`, avoiding cert/signature confusion (`WsseService.kt:172-186`).
- **Santuario duplicate-id XSW protection** is active (secureValidation default), blocking the classic copy-paste wrapping variant.
- **CAdES-T timestamp binding** correctly enforces `messageImprint` matching the outer signer signature and treats a present-but-failing TSP attribute as fatal (`CmsService.kt:255-296`, `TspService.kt:145-151`) — stricter than upstream NCANode v3.
- **OCSP nonce matching, CertID issuer construction, and the CA-direct-signing branch** verify correctly (the responder-cert validity/revocation gap M-2 is confined to the delegated-responder sub-branch).
- **XML zero-signature guard** is present (`XmlService.kt:143`, `WsseService.kt:156-158`) — the CMS equivalent (H-1) is the one that's missing.

**Bottom line:** the math is right and cert binding is careful; the defects are concentrated in *coverage assertion* (H-3, H-4, M-1), *empty/missing-input guards* (H-1, H-2), and *full RFC 5280 §6 path processing* (the low cluster). Fix H-1 through H-4 and M-1/M-2 first — those are the ones a `valid`-flag-trusting caller can be deceived by today.