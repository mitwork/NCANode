package kz.ncanode.service

import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.pdf.PdfSignerInfo
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.response.PdfSignResponse
import kz.ncanode.dto.response.PdfVerificationResponse
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.exception.NoSignaturesFoundException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.KeyStoreWrapper
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Calendar
import java.util.Date
import java.util.Vector

@Service
class PdfService(
    private val kalkanWrapper: KalkanWrapper,
    private val tspService: TspService,
    private val certificateService: CertificateService,
) {

    /**
     * Signs a PDF document with digital signature.
     */
    fun sign(pdfSignRequest: PdfSignRequest): PdfSignResponse = try {
        val pdfBytes = Base64.getDecoder().decode(pdfSignRequest.pdf)

        Loader.loadPDF(pdfBytes).use { document ->
            for (pdfSigner in pdfSignRequest.signers) {
                val keyStoreWrapper = kalkanWrapper.read(listOf(pdfSigner.signer))[0]

                val signature = PDSignature().apply {
                    setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                    setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED) // ETSI CADES
                    setName(keyStoreWrapper.certificate.x509Certificate.subjectX500Principal.name)
                    setLocation(pdfSigner.location)
                    setReason(pdfSigner.reason)
                    setContactInfo(pdfSigner.contactInfo)
                    setSignDate(Calendar.getInstance())
                }

                document.addSignature(
                    signature,
                    PdfSignatureInterface(keyStoreWrapper, pdfSignRequest.isWithTsp, pdfSignRequest.tsaPolicy),
                )
            }

            val outputStream = ByteArrayOutputStream()
            document.saveIncremental(outputStream)
            PdfSignResponse(pdf = Base64.getEncoder().encodeToString(outputStream.toByteArray()))
        }
    } catch (e: Exception) {
        log.error("Error signing PDF", e)
        throw ServerException("Error signing PDF: ${e.message}", e)
    }

    /**
     * Verifies digital signatures in a PDF document.
     */
    fun verify(pdfVerifyRequest: PdfVerifyRequest): PdfVerificationResponse {
        try {
            val pdfBytes = Base64.getDecoder().decode(pdfVerifyRequest.pdf)

            Loader.loadPDF(pdfBytes).use { document ->
                val signatures = document.signatureDictionaries
                if (signatures.isEmpty()) {
                    throw NoSignaturesFoundException("PDF document contains no digital signatures")
                }

                val signerInfos = mutableListOf<PdfSignerInfo>()
                var allValid = true

                for (signature in signatures) {
                    val signerInfo = verifySignature(signature, pdfVerifyRequest, pdfBytes)
                    signerInfos.add(signerInfo)
                    if (!signerInfo.isValid) allValid = false
                }

                return PdfVerificationResponse(valid = allValid, signers = signerInfos)
            }
        } catch (e: NoSignaturesFoundException) {
            throw e
        } catch (e: Exception) {
            throw ServerException("Error verifying PDF: ${e.message}", e)
        }
    }

    /**
     * Verifies a single PDSignature using the original PDF bytes and CertificateService.
     */
    private fun verifySignature(
        signature: PDSignature,
        pdfVerifyRequest: PdfVerifyRequest,
        originalPdfBytes: ByteArray,
    ): PdfSignerInfo {
        try {
            // 1) Extract raw CMS (the /Contents) and the signed content (ByteRange)
            val signatureContent = signature.contents
            if (signatureContent == null || signatureContent.isEmpty()) {
                return PdfSignerInfo(isValid = false, reason = "Empty signature contents")
            }

            val signedContent = originalPdfBytes.inputStream().use { signature.getSignedContent(it) }

            // 2) Parse CMS and iterate signer infos
            val signedData = CMSSignedData(CMSProcessableByteArray(signedContent), signatureContent)
            @Suppress("UNCHECKED_CAST")
            val signers = signedData.signerInfos.signers as Collection<SignerInformation>

            var valid = false
            var certificateWrapper: CertificateWrapper? = null
            var digestAlgReported: String? = null

            val certStore = signedData.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            val withOcsp = CertificateRevocation.OCSP in pdfVerifyRequest.revocationCheck
            val withCrl = CertificateRevocation.CRL in pdfVerifyRequest.revocationCheck
            val now = Date()
            var validationDate = now

            for (si in signers) {
                val certCollection = certStore.getCertificates(si.sid)
                if (certCollection == null || certCollection.isEmpty()) continue

                val x509 = certCollection.iterator().next() as X509Certificate

                // 3) Cryptographic verification of CMS signature using Kalkan provider
                if (!si.verify(x509.publicKey, KalkanProvider.PROVIDER_NAME)) continue

                // 3a) CAdES-T: если у подписанта есть signature-timestamp, проверяем его
                // и используем genTime метки как "момент истины" для проверки срока
                // действия сертификата (RFC 5126). Иначе подпись с истёкшим cert'ом
                // и валидной TSP-меткой считалась бы невалидной — что неверно.
                validationDate = now
                val verifiedTsp = extractAndVerifyTsp(si, withOcsp, withCrl)
                when {
                    verifiedTsp != null && verifiedTsp.genTime != null -> validationDate = verifiedTsp.genTime
                    hasTspAttribute(si) -> {
                        // TSP заявлен подписантом, но не прошёл строгую проверку —
                        // в CAdES-T это делает всю подпись невалидной.
                        log.warn("PDF signer has TSP attribute but verification failed")
                        continue
                    }
                }

                // 4) Trust + revocation validation via CertificateService
                certificateWrapper = CertificateWrapper(x509)
                certificateService.attachValidationData(certificateWrapper, withOcsp, withCrl)

                if (!certificateWrapper.isValid(validationDate, withOcsp, withCrl)) {
                    // Keep looping if multiple signer infos exist; otherwise report invalid
                    continue
                }

                // If we reached here → both CMS signature and trust checks are OK
                valid = true

                // 5) Record digest OID (if you want to surface it)
                digestAlgReported = try {
                    si.digestAlgOID
                } catch (e: Exception) {
                    null
                }
                break
            }

            return PdfSignerInfo(
                isValid = valid,
                reason = signature.reason,
                location = signature.location,
                contactInfo = signature.contactInfo,
                signDate = signature.signDate?.time,
                certificate = certificateWrapper?.toCertificateInfo(validationDate, withOcsp, withCrl),
                // Keep your current semantics:
                // - signatureAlgorithm shows PDF SubFilter (structure-level)
                // - digestAlgorithm shows CMS digest OID (crypto-level)
                signatureAlgorithm = signature.subFilter,
                digestAlgorithm = digestAlgReported ?: "unknown",
            )
        } catch (e: Exception) {
            log.error("Error verifying signature", e)
            return PdfSignerInfo(isValid = false, reason = "Verification error: ${e.message}")
        }
    }

    /**
     * Проверяет, есть ли у подписанта прицепленная TSP-метка времени.
     * Используется чтобы отличить "TSP не было" (валидная BES-подпись)
     * от "TSP был, но не прошёл проверку" (невалидная T-подпись).
     */
    private fun hasTspAttribute(si: SignerInformation): Boolean {
        val unsigned = si.unsignedAttributes ?: return false
        return unsigned.toHashtable().containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
    }

    /**
     * Извлекает TSP-токен из unsigned attributes подписанта и прогоняет через
     * [TspService.verify]. Возвращает информацию о метке, только если все
     * проверки прошли (подпись TSA, messageImprint, EKU, валидность цепочки
     * TSA на genTime).
     */
    private fun extractAndVerifyTsp(si: SignerInformation, checkOcsp: Boolean, checkCrl: Boolean): TimeStampTokenInfo? {
        if (!hasTspAttribute(si)) return null
        return try {
            val obj = si.unsignedAttributes.toHashtable()[PKCSObjectIdentifiers.id_aa_signatureTimeStampToken]
            val attr = when (obj) {
                is Vector<*> -> obj[0] as Attribute
                else -> obj as Attribute
            }
            if (attr.attrValues.size() != 1) {
                log.warn("PDF signer has multiple TSP tokens, rejecting")
                return null
            }
            val tspCms = CMSSignedData(attr.attrValues.getObjectAt(0).derObject.encoded)
            tspService.verify(tspCms, si.signature, checkOcsp, checkCrl)
        } catch (e: Exception) {
            log.warn("Failed to extract TSP from PDF signer: {}", e.message)
            null
        }
    }

    /**
     * Custom signature interface for PDFBox.
     */
    private inner class PdfSignatureInterface(
        private val keyStoreWrapper: KeyStoreWrapper,
        private val withTsp: Boolean,
        private val tsaPolicy: TsaPolicy?,
    ) : SignatureInterface {

        @Throws(IOException::class)
        override fun sign(content: InputStream): ByteArray {
            try {
                val cert = keyStoreWrapper.certificate.x509Certificate
                val privateKey = keyStoreWrapper.privateKey

                val contentBytes = content.readBytes()

                val generator = CMSSignedDataGenerator()
                // Add signer using the same pattern as CmsService
                generator.addSigner(
                    privateKey, cert,
                    getDigestAlgorithmOidBYSignAlgorithmOid(cert.sigAlgOID),
                )

                val certStore = CertStore.getInstance(
                    "Collection",
                    CollectionCertStoreParameters(listOf(cert)),
                    KalkanProvider.PROVIDER_NAME,
                )
                generator.addCertificatesAndCRLs(certStore)

                var signedData = generator.generate(
                    CMSProcessableByteArray(contentBytes), false, KalkanProvider.PROVIDER_NAME,
                )

                if (withTsp) {
                    val useTsaPolicy = tsaPolicy?.policyId ?: TsaPolicy.TSA_GOST2015_POLICY.policyId

                    val newSigners = signedData.signerInfos.signers.map { signer ->
                        tspService.addTspToSigner(signer as SignerInformation, cert, useTsaPolicy)
                    }

                    signedData = CMSSignedData.replaceSigners(signedData, SignerInformationStore(newSigners))
                }

                return signedData.encoded
            } catch (e: Exception) {
                log.error("Error creating signature", e)
                throw IOException("Error creating signature", e)
            }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(PdfService::class.java)
    }
}
