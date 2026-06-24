# PKI RFC-compliance — план работ

Источник: `pki-rfc-audit-report.md` (multi-agent аудит, 12 подтверждённых
находок из 35, 23 отсеяны верификаторами). Корневая причина всех HIGH —
`VerificationResponse` отдаёт плоский `valid`, не сообщая, **что именно**
покрыто подписью.

Легенда статуса: ⬜ TODO · 🔶 в работе · ✅ сделано

## Пункт 1 — verification-contract в CMS + OCSP responder ✅ ГОТОВО

| # | Sev | Находка | Где | Статус |
|---|---|---|---|---|
| 1.1 | HIGH | CMS с 0 подписантов → `valid=true` | `CmsService.kt:241-247` | ✅ |
| 1.2 | HIGH | Подписант без cert в store → молча ОК (подпись не проверена) | `CmsService.kt:303-313` | ✅ |
| 1.3 | MED | Cert делегированного OCSP-responder'а не проверен на validity | `OcspService.kt:275-300` | ✅ |

Фиксы: guard на пустой `signerInfos` (return valid=false) + guard `certs.isEmpty()`
per-signer; в OCSP — `checkValidity(producedAt)` + учёт `id-pkix-ocsp-nocheck`.
Тесты: 2 в `CmsServiceIntegrationTest` (zero-signers, cert-stripped). Сьют 192/0.

## Пункт 2 — покрытие документа подписью ✅ ГОТОВО

| # | Sev | Находка | Где | Статус |
|---|---|---|---|---|
| 2.1 | HIGH | XML-DSig не проверяет, что Reference покрывает документ (XSW) | `XMLSignatureWrapper.coversWholeDocument`, `XmlService.kt` | ✅ |
| 2.2 | HIGH | PDF не проверяет `/ByteRange` на весь файл (PAdES incremental-update) | `PdfService.signatureCoversWholeDocument` | ✅ |
| 2.3 | MED | WSSE не проверяет, что подпись покрывает SOAP Body (move-original XSW) | `WsseService.signatureReferencesId` | ✅ |

Фиксы:
- **2.1** — `coversWholeDocument()`: требуем Reference с пустым URI + только
  безопасные transforms (enveloped + c14n); иначе XSW. `PdfSignerInfo`-аналога нет,
  встроено в `XmlService.verify`.
- **2.2** — `signatureCoversWholeDocument()`: `/ByteRange` от 0 до EOF; на уровне
  документа требуем, чтобы хотя бы одна подпись покрывала весь файл (multi-sign
  safe). Новый флаг `PdfSignerInfo.coversWholeDocument`.
- **2.3** — регистрируем `wsu:Id` ровно на настоящем Body + `secureValidation=true`
  + явная проверка, что Reference ссылается на body id; per-signature try/catch
  (битая подпись → valid=false, не 500).

Тесты: +2 PDF (forgery + whole-doc), +2 XML (coversWholeDocument: ""/`#x`),
+1 WSSE (broken body binding). Сьют 192 → **197**.

## Пункт 3 — LOW conformance (бэклог)

| # | Находка | Где | Статус |
|---|---|---|---|
| 3.1 | TSA EKU: проверять criticality + sole-EKU (RFC 3161 §2.3) | `TspService.kt:153-158` | ⬜ |
| 3.2 | NPE на cert без keyUsage extension (RFC 5280 §4.2.1.3) | `CertificateWrapper.kt:75`, `CertificateKeyUsage.kt` | ⬜ |
| 3.3 | Unrecognized critical extensions (cert) не reject'ятся (§4.2) | `CertificateWrapper.kt:155-168` | ⬜ |
| 3.4 | Unrecognized critical extensions (CRL) не reject'ятся (§5.2) | `CrlService.kt:240-305` | ⬜ |

## Пункт 4 — редизайн через JDK PKIX (большой, опционально)

Прогнать trust-решение через `CertPathValidator` / `PKIXParameters` +
`PKIXRevocationChecker` с CA-bundle как TrustAnchors. Закрыло бы разом:
RFC 5280 §6 path validation (basicConstraints/pathLen/nameConstraints,
LOW), revocation промежуточных CA (LOW), и critical-ext rejection (3.3/3.4).
Не точечный фикс — отдельное проектное решение.

Подтверждённый нюанс из аудита: §6 — всего LOW, т.к. `getRootCertificateFor`
требует `cert.verify(root)` против operator-pinned bundle → чужой intermediate
не подсунуть; не хватает только обработки constraints, а не доверия.
