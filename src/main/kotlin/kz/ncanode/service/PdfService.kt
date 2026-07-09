package kz.ncanode.service

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo
import kz.ncanode.dto.pdf.PdfSignerInfo
import kz.ncanode.dto.request.PdfSignBatchRequest
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyBatchRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.response.PdfSignBatchResponse
import kz.ncanode.dto.response.PdfSignResponse
import kz.ncanode.dto.response.PdfVerificationResponse
import kz.ncanode.dto.response.PdfVerifyBatchResponse
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.NoSignaturesFoundException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.mapPartial
import kz.ncanode.util.warnIfRevocationDisabled
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
                // Валидация (@NotNull @Valid) отсекает null раньше, но тип
                // nullable — оставляем защитный null-check как 400, не как NPE.
                val signerRequest = pdfSigner.signer
                    ?: throw ClientException("signer must be specified")
                val keyStoreWrapper = kalkanWrapper.read(listOf(signerRequest))[0]

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
    } catch (e: ApplicationException) {
        // Намеренный 400 (пустой ключ/пароль из KalkanWrapper, отсутствующий
        // signer) не заворачиваем в 500.
        throw e
    } catch (e: Exception) {
        log.error("Error signing PDF", e)
        throw ServerException("Error signing PDF: ${e.message}", e)
    }

    /**
     * Batch-подпись PDF: каждый PDF в [PdfSignBatchRequest.pdfs] подписывается
     * общим набором signer'ов и одинаковыми TSP/политикой. Partial-response.
     */
    fun signBatch(request: PdfSignBatchRequest): PdfSignBatchResponse {
        val items = request.pdfs.mapPartial({ status, message ->
            PdfSignBatchResponse.Item(status = status, message = message)
        }) { pdf ->
            val itemRequest = PdfSignRequest().apply {
                this.pdf = pdf
                this.signers = request.signers
                this.isWithTsp = request.isWithTsp
                this.tsaPolicy = request.tsaPolicy
            }
            PdfSignBatchResponse.Item(pdf = sign(itemRequest).pdf)
        }
        return PdfSignBatchResponse(results = items)
    }

    /**
     * Batch-верификация PDF: каждый PDF проверяется независимо.
     */
    fun verifyBatch(request: PdfVerifyBatchRequest): PdfVerifyBatchResponse {
        val items = request.pdfs.mapPartial({ status, message ->
            PdfVerificationResponse(valid = false, status = status, message = message)
        }) { pdf ->
            verify(PdfVerifyRequest().apply {
                this.pdf = pdf
                this.revocationCheck = request.revocationCheck
            })
        }
        return PdfVerifyBatchResponse(results = items)
    }

    /**
     * Verifies digital signatures in a PDF document.
     */
    fun verify(pdfVerifyRequest: PdfVerifyRequest): PdfVerificationResponse {
        warnIfRevocationDisabled(
            pdfVerifyRequest.checkOcsp,
            pdfVerifyRequest.checkCrl,
        )
        try {
            val pdfBytes = Base64.getDecoder().decode(pdfVerifyRequest.pdf)

            Loader.loadPDF(pdfBytes).use { document ->
                val signatures = document.signatureDictionaries
                if (signatures.isEmpty()) {
                    throw NoSignaturesFoundException("PDF document contains no digital signatures")
                }

                val fileLength = pdfBytes.size
                val signerInfos = mutableListOf<PdfSignerInfo>()
                var allValid = true
                var wholeDocumentCovered = false

                for (signature in signatures) {
                    // PAdES / ISO 32000-1 §12.8.1: подпись защищает только байты
                    // своего /ByteRange. Если ByteRange не доходит до EOF —
                    // после подписанной ревизии дописан incremental update,
                    // который никто не подписывал.
                    val coversWhole = signatureCoversWholeDocument(signature, fileLength)
                    if (coversWhole) wholeDocumentCovered = true

                    val signerInfo = verifySignature(signature, pdfVerifyRequest, pdfBytes, coversWhole)
                    signerInfos.add(signerInfo)
                    if (!signerInfo.isValid) allValid = false
                }

                // Документ цел, только если хотя бы одна подпись покрывает его
                // целиком: для multi-sign это последняя подпись (она подписывает
                // и предыдущие ревизии). Иначе есть неподписанный хвост — весь
                // результат верификации обесценивается.
                if (!wholeDocumentCovered) {
                    log.warn("PDF has signatures but none covers the whole document — content appended after signing")
                }

                return PdfVerificationResponse(
                    valid = allValid && wholeDocumentCovered,
                    signers = signerInfos,
                )
            }
        } catch (e: NoSignaturesFoundException) {
            throw e
        } catch (e: Exception) {
            throw ServerException("Error verifying PDF: ${e.message}", e)
        }
    }

    /**
     * PAdES / ISO 32000-1 §12.8.1: подпись покрывает весь документ, только если
     * её `/ByteRange` начинается с 0 и доходит до конца файла, оставляя
     * единственную дыру под `/Contents`. Любой неподписанный хвост (incremental
     * update после подписания) делает результат false.
     */
    private fun signatureCoversWholeDocument(signature: PDSignature, fileLength: Int): Boolean {
        val byteRange = signature.byteRange ?: return false
        if (byteRange.size != 4) return false
        val (start1, len1, start2, len2) = byteRange
        // Валидный ByteRange: [0, a, b, c], где дыра [a, b) — это /Contents.
        if (start1 != 0 || len1 < 0 || len2 < 0 || start2 < len1) return false
        val coveredEnd = start2.toLong() + len2.toLong()
        return coveredEnd == fileLength.toLong()
    }

    /**
     * Verifies a single PDSignature using the original PDF bytes and CertificateService.
     */
    private fun verifySignature(
        signature: PDSignature,
        pdfVerifyRequest: PdfVerifyRequest,
        originalPdfBytes: ByteArray,
        coversWholeDocument: Boolean,
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
            val certStore = signedData.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            val withOcsp = pdfVerifyRequest.checkOcsp
            val withCrl = pdfVerifyRequest.checkCrl
            val now = Date()

            // Ищем первого полностью валидного подписанта. Непригодный signer →
            // пробуем следующего; cert/validationDate ПОСЛЕДНЕЙ попытки (даже
            // провальной по trust) отражаются в ответе — исходная семантика.
            var valid = false
            var certificateWrapper: CertificateWrapper? = null
            var validationDate = now
            var digestAlgReported: String? = null
            for (si in signers) {
                val attempt = verifyPdfSigner(si, certStore, withOcsp, withCrl, now) ?: continue
                certificateWrapper = attempt.certificate
                validationDate = attempt.validationDate
                if (attempt.valid) {
                    valid = true
                    digestAlgReported = attempt.digest
                    break
                }
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
                coversWholeDocument = coversWholeDocument,
            )
        } catch (e: Exception) {
            log.error("Error verifying signature", e)
            return PdfSignerInfo(isValid = false, reason = "Verification error: ${e.message}")
        }
    }

    private data class PdfSignerAttempt(
        val valid: Boolean,
        val certificate: CertificateWrapper,
        val validationDate: Date,
        val digest: String?,
    )

    /**
     * Попытка проверить одного CMS-подписанта PDF. `null` — signer непригоден
     * (нет cert'а / не прошёл криптопроверку / TSP заявлен, но не прошёл): цикл
     * пробует следующего. Иначе результат с флагом [PdfSignerAttempt.valid]
     * (true — крипто+TSP+trust ОК; false — trust не прошёл, но cert записан).
     */
    private fun verifyPdfSigner(
        si: SignerInformation,
        certStore: CertStore,
        withOcsp: Boolean,
        withCrl: Boolean,
        now: Date,
    ): PdfSignerAttempt? {
        val certCollection = certStore.getCertificates(si.sid)
        if (certCollection == null || certCollection.isEmpty()) return null
        val x509 = certCollection.iterator().next() as X509Certificate

        // Криптопроверка подписи CMS через Kalkan.
        if (!si.verify(x509.publicKey, KalkanProvider.PROVIDER_NAME)) return null

        // CAdES-T: при валидной TSP-метке её genTime — "момент истины" для срока
        // действия cert'а (RFC 5126). TSP заявлен, но не прошёл → подпись невалидна.
        var validationDate = now
        val verifiedTsp = extractAndVerifyTsp(si, withOcsp, withCrl)
        when {
            verifiedTsp != null && verifiedTsp.genTime != null -> validationDate = verifiedTsp.genTime
            tspService.hasTimestampAttribute(si) -> {
                log.warn("PDF signer has TSP attribute but verification failed")
                return null
            }
        }

        // Trust + revocation.
        val certificateWrapper = CertificateWrapper(x509)
        certificateService.attachValidationData(certificateWrapper, withOcsp, withCrl)
        if (!certificateWrapper.isValid(validationDate, withOcsp, withCrl)) {
            return PdfSignerAttempt(false, certificateWrapper, validationDate, digest = null)
        }

        val digest = try { si.digestAlgOID } catch (e: Exception) { null }
        return PdfSignerAttempt(true, certificateWrapper, validationDate, digest)
    }

    /**
     * Извлекает TSP-токен из unsigned attributes подписанта и прогоняет через
     * [TspService.verify]. Возвращает информацию о метке, только если все
     * проверки прошли (подпись TSA, messageImprint, EKU, валидность цепочки
     * TSA на genTime).
     */
    private fun extractAndVerifyTsp(si: SignerInformation, checkOcsp: Boolean, checkCrl: Boolean): TimeStampTokenInfo? = try {
        tspService.extractTimestampToken(si)?.let { tspService.verify(it, si.signature, checkOcsp, checkCrl) }
    } catch (e: Exception) {
        log.warn("Failed to extract/verify TSP from PDF signer: {}", e.message)
        null
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
