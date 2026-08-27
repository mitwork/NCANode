package kz.ncanode.service

import kz.gov.pki.kalkan.asn1.cms.AttributeTable
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.ncanode.ades.CadesAttributes
import kz.ncanode.ades.PadesInspector
import kz.ncanode.ades.PdfDocumentSecurityStore
import kz.ncanode.ades.PdfIncrementalUpdate
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.PadesSignatureInfo
import kz.ncanode.dto.request.PadesSignBatchRequest
import kz.ncanode.dto.request.PadesSignRequest
import kz.ncanode.dto.request.PadesVerifyBatchRequest
import kz.ncanode.dto.request.PadesVerifyRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.response.PadesResponse
import kz.ncanode.dto.response.PadesSignBatchResponse
import kz.ncanode.dto.response.PadesVerificationBatchResponse
import kz.ncanode.dto.response.PadesVerificationResponse
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getTspHashAlgorithmByOid
import kz.ncanode.util.mapPartial
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.KeyStoreWrapper
import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Calendar

/**
 * Подпись PAdES по ETSI EN 319 142-1.
 *
 * От `/pdf/sign` отличается составом CMS и трактовкой уровней; тот эндпойнт
 * не легаси и работает как прежде.
 *
 * Профиль PAdES по-своему обходится с атрибутами: в CMS кладётся **только**
 * `signingCertificateV2`, без `signingTime` — время подписи несёт запись `/M`
 * словаря подписи, и дублировать его в CMS не следует (см.
 * [CadesAttributes.padesSignedAttributes]).
 *
 * Реализованы уровни B, T, LT и LTA. Каждая подпись добавляется отдельным
 * инкрементальным обновлением файла: только так PDF может нести несколько
 * подписей, не разрушая предыдущие. Данные для проверки (LT) добавляются
 * последним обновлением поверх всех подписей.
 */
@Service
class PadesService(
    private val kalkanWrapper: KalkanWrapper,
    private val tspService: TspService,
    private val pdfService: PdfService,
    private val validationDataService: ValidationDataService,
) {

    fun sign(request: PadesSignRequest): PadesResponse {
        return try {
            var pdf = decodePdf(request.pdf)
            val signerCertificates = mutableListOf<X509Certificate>()
            for (signer in request.signers) {
                val keyStore = kalkanWrapper.read(
                    listOf(signer.signer ?: throw ClientException("signer must be specified")),
                )[0]
                signerCertificates.add(keyStore.certificate.x509Certificate)
                pdf = embedSignature(pdf, signer, keyStore, request.level, request.tsaPolicy)
            }
            if (request.level.isAtLeast(AdesLevel.LT)) {
                pdf = embedValidationData(pdf, signerCertificates)
            }
            if (request.level.isAtLeast(AdesLevel.LTA)) {
                pdf = addDocumentTimestamp(pdf, signerCertificates.last(), request.tsaPolicy)
            }
            PadesResponse(pdf = Base64.getEncoder().encodeToString(pdf), level = request.level)
        } catch (e: ApplicationException) {
            throw e
        } catch (e: Exception) {
            log.error("Error signing PAdES", e)
            throw ServerException("Error signing PAdES: ${e.message}", e)
        }
    }

    /**
     * Проверяет PAdES и сообщает уровень.
     *
     * Криптография, цепочка, отзыв и покрытие документа берутся из
     * [PdfService.verify]. Здесь добавляется AdES-специфика: заявленный
     * уровень, сверка привязки `signingCertificateV2` и отделение документных
     * меток времени от подписей.
     *
     * Документные метки (`/DocTimeStamp`) в [PdfService.verify] попадают в
     * общий перебор словарей подписей, поэтому их вердикт исключается из
     * итогового: метка — не подпись, и оценивать её как подписанта неверно.
     * Проверяются они отдельно — как токены RFC 3161 над покрытыми байтами.
     */
    fun verify(request: PadesVerifyRequest): PadesVerificationResponse {
        val pdfBytes = decodePdf(request.pdf)

        val facts = try {
            PadesInspector.inspect(pdfBytes, kalkanWrapper.kalkanProvider)
        } catch (e: Exception) {
            log.warn("Cannot inspect PAdES structure: {}", e.message)
            emptyList()
        }

        // Материал из `/DSS` достаём заранее: он нужен прямо внутри проверки,
        // до того как та пойдёт в сеть.
        val embedded = if ((request.checkOcsp || request.checkCrl) &&
            facts.any { it.level.isAtLeast(AdesLevel.LT) }
        ) {
            try {
                PadesInspector.embeddedMaterial(pdfBytes)
            } catch (e: Exception) {
                log.warn("Cannot read the /DSS validation data: {}", e.message)
                null
            }
        } else {
            null
        }
        var embeddedUsed = false

        val base = pdfService.verify(
            PdfVerifyRequest().apply {
                pdf = request.pdf
                revocationCheck = request.revocationCheck
            },
        ) { certificate, at ->
            // Момент приходит из PdfService — это genTime метки подписи, если
            // она валидна. Данные об отзыве авторитетны только на своём
            // интервале, поэтому именно он и решает, какой источник подойдёт.
            if (embedded != null &&
                validationDataService.attachEmbedded(certificate, embedded.crls, embedded.ocspResponses, at)
            ) {
                embeddedUsed = true
            }
        }

        val signatures = mutableListOf<PadesSignatureInfo>()
        var documentTimestamps = 0
        var bindingsValid = true
        // Вердикт по документным меткам берём из общей проверки: PdfService
        // теперь проверяет их как метки, а не как подписи, и второй раз
        // разбирать документ незачем.
        val stamps = base.signers.filter { it.documentTimestamp }
        val documentTimestampsValid = stamps.isNotEmpty() && stamps.all { it.isValid }

        base.signers.forEachIndexed { index, signer ->
            val signatureFacts = facts.getOrNull(index)
            if (signatureFacts?.documentTimestamp == true) {
                documentTimestamps++
                return@forEachIndexed
            }
            if (signatureFacts != null && !signatureFacts.signingCertificateMatches) {
                bindingsValid = false
            }
            signatures.add(
                PadesSignatureInfo(
                    level = signatureFacts?.level,
                    verifiedLevel = signatureFacts?.level?.let { claimed ->
                        verifiedLevel(
                            claimed = claimed,
                            timestamped = signatureFacts.level.isAtLeast(AdesLevel.T) && signer.isValid,
                            embeddedUsed = embeddedUsed,
                            archiveValid = documentTimestampsValid,
                        )
                    },
                    signer = signer,
                ),
            )
        }

        val valid = if (documentTimestamps == 0) {
            base.valid && bindingsValid
        } else {
            // Пересобираем вердикт по тому же правилу, что и PdfService
            // (все подписи валидны И покрытие документа приемлемо), но без
            // документных меток.
            signatures.all { it.signer?.isValid == true } &&
                PdfIncrementalUpdate.coverageAcceptable(pdfBytes) &&
                bindingsValid
        }

        return PadesVerificationResponse(
            valid = valid,
            level = signatures.mapNotNull { it.level }.minByOrNull { it.ordinal },
            verifiedLevel = signatures.mapNotNull { it.verifiedLevel }.minByOrNull { it.ordinal },
            signatures = signatures,
            documentTimestamps = documentTimestamps,
        )
    }

    /**
     * До какого уровня подпись **подтверждена**: метка времени для T,
     * использованный материал из `/DSS` для LT, проверенная документная метка
     * для LTA.
     */

    /**
     * Batch-подпись: каждый PDF подписывается независимо общим набором
     * signer'ов до общего уровня. Метаданные подписанта, включая видимое
     * представление, общие — они часть подписанта, а не документа.
     */
    fun signBatch(request: PadesSignBatchRequest): PadesSignBatchResponse {
        val items = request.pdfs.mapPartial({ status, message ->
            PadesSignBatchResponse.Item(status = status, message = message)
        }) { pdf ->
            val response = sign(
                PadesSignRequest().apply {
                    this.pdf = pdf
                    this.signers = request.signers
                    this.level = request.level
                    this.tsaPolicy = request.tsaPolicy
                },
            )
            PadesSignBatchResponse.Item(pdf = response.pdf, level = response.level)
        }
        return PadesSignBatchResponse(results = items)
    }

    /** Batch-проверка: каждый PDF проверяется независимо с общими флагами. */
    fun verifyBatch(request: PadesVerifyBatchRequest): PadesVerificationBatchResponse {
        val items = request.pdfs.mapPartial({ status, message ->
            PadesVerificationResponse(valid = false, status = status, message = message)
        }) { pdf ->
            verify(
                PadesVerifyRequest().apply {
                    this.pdf = pdf
                    revocationCheck = request.revocationCheck
                },
            )
        }
        return PadesVerificationBatchResponse(results = items)
    }

    private fun verifiedLevel(
        claimed: AdesLevel,
        timestamped: Boolean,
        embeddedUsed: Boolean,
        archiveValid: Boolean,
    ): AdesLevel = when {
        claimed.isAtLeast(AdesLevel.LTA) && archiveValid && embeddedUsed -> AdesLevel.LTA
        claimed.isAtLeast(AdesLevel.LT) && embeddedUsed -> AdesLevel.LT
        claimed.isAtLeast(AdesLevel.T) && timestamped -> AdesLevel.T
        else -> AdesLevel.B
    }

    /**
     * Встраивает данные для проверки в словарь `/DSS` — уровень LT.
     *
     * Добавляется инкрементальным обновлением: подписи не трогаются и
     * остаются валидными. Такой хвост наша проверка принимает, потому что он
     * не меняет отображаемое содержимое (см.
     * [kz.ncanode.ades.PdfIncrementalUpdate]).
     */
    private fun embedValidationData(pdf: ByteArray, signerCertificates: List<X509Certificate>): ByteArray {
        val certificates = mutableListOf<X509Certificate>()
        val crls = mutableListOf<java.security.cert.X509CRL>()
        val ocspResponses = mutableListOf<ByteArray>()

        for (certificate in signerCertificates.distinct()) {
            val data = validationDataService.collect(certificate)
            certificates.addAll(data.certificates)
            crls.addAll(data.crls)
            ocspResponses.addAll(data.ocspResponses)
        }

        return Loader.loadPDF(pdf).use { document ->
            PdfDocumentSecurityStore.add(document, certificates.distinct(), crls, ocspResponses)
            val output = ByteArrayOutputStream()
            document.saveIncremental(output)
            output.toByteArray()
        }
    }

    /**
     * Добавляет документную метку времени — уровень LTA.
     *
     * Это отдельный словарь подписи с типом `/DocTimeStamp`, чьё содержимое —
     * сам токен RFC 3161. Метка ставится последней и покрывает файл целиком
     * вместе с `/DSS`: тем самым непокрытого хвоста в документе не остаётся.
     */
    private fun addDocumentTimestamp(
        pdf: ByteArray,
        certificate: X509Certificate,
        tsaPolicy: TsaPolicy?,
    ): ByteArray {
        val policyId = (tsaPolicy ?: TsaPolicy.TSA_GOST2015_POLICY).policyId
        val digestOid = getTspHashAlgorithmByOid(certificate.sigAlgOID)

        Loader.loadPDF(pdf).use { document ->
            val timestamp = PDSignature().apply {
                setType(COSName.getPDFName("DocTimeStamp"))
                setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                setSubFilter(COSName.getPDFName("ETSI.RFC3161"))
            }
            val signer = DocumentTimestampSigner(digestOid, policyId)
            val options = SignatureOptions().apply { preferredSignatureSize = TIMESTAMP_RESERVE }
            try {
                document.addSignature(timestamp, signer, options)
                val output = ByteArrayOutputStream()
                document.saveIncremental(output)
                signer.failure?.let { throw it }
                return output.toByteArray()
            } finally {
                options.close()
            }
        }
    }

    private fun embedSignature(
        pdf: ByteArray,
        padesSigner: PadesSignRequest.PadesSigner,
        keyStore: KeyStoreWrapper,
        level: AdesLevel,
        tsaPolicy: TsaPolicy?,
    ): ByteArray {
        Loader.loadPDF(pdf).use { document ->
            val signature = PDSignature().apply {
                setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                // Правильный SubFilter для PAdES: CMS лежит отдельно от документа.
                setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED)
                setName(padesSigner.name ?: keyStore.certificate.x509Certificate.subjectX500Principal.name)
                padesSigner.reason?.let { setReason(it) }
                padesSigner.location?.let { setLocation(it) }
                padesSigner.contactInfo?.let { setContactInfo(it) }
                setSignDate(Calendar.getInstance())
            }

            val signer = PadesCmsSigner(keyStore, level, tsaPolicy)
            val options = visibleSignatureOptions(document, padesSigner.visibleSignature)
            try {
                if (options != null) {
                    document.addSignature(signature, signer, options)
                } else {
                    document.addSignature(signature, signer)
                }

                val output = ByteArrayOutputStream()
                document.saveIncremental(output)
                // PDFBox заворачивает нашу ошибку в IOException и теряет тип;
                // поднимаем оригинал, чтобы плохой пароль p12 остался 400.
                signer.failure?.let { throw it }
                return output.toByteArray()
            } finally {
                options?.close()
            }
        }
    }

    /**
     * Готовит размещение видимой подписи. Внешний вид приходит готовым
     * PDF-шаблоном — рисование остаётся на стороне вызывающего, как и в
     * NCALayer.
     */
    private fun visibleSignatureOptions(
        document: PDDocument,
        visibleSignature: PadesSignRequest.VisibleSignature?,
    ): SignatureOptions? {
        if (visibleSignature == null) return null

        if (visibleSignature.page > document.numberOfPages) {
            throw ClientException(
                "Visible signature page ${visibleSignature.page} is out of range, " +
                    "the document has ${document.numberOfPages} page(s)",
            )
        }
        val template = try {
            Base64.getDecoder().decode(visibleSignature.template)
        } catch (e: IllegalArgumentException) {
            throw ClientException("Visible signature template is not valid base64")
        }

        return SignatureOptions().apply {
            setVisualSignature(ByteArrayInputStream(template))
            setPage(visibleSignature.page - 1)
        }
    }

    /**
     * Собирает detached-CMS над байтами, которые PDFBox покрывает `/ByteRange`.
     */
    private fun buildDetachedCms(
        keyStore: KeyStoreWrapper,
        content: ByteArray,
        level: AdesLevel,
        tsaPolicy: TsaPolicy?,
    ): ByteArray {
        val certificate = keyStore.certificate.x509Certificate
        val digestAlgorithmOid = getDigestAlgorithmOidBYSignAlgorithmOid(certificate.sigAlgOID)

        val generator = CMSSignedDataGenerator()
        generator.addSigner(
            keyStore.privateKey,
            certificate,
            digestAlgorithmOid,
            CadesAttributes.padesSignedAttributes(certificate, kalkanWrapper.kalkanProvider),
            null as AttributeTable?,
        )
        generator.addCertificatesAndCRLs(
            CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(certificateChain(keyStore)),
                KalkanProvider.PROVIDER_NAME,
            ),
        )

        var cms = generator.generate(CMSProcessableByteArray(content), false, KalkanProvider.PROVIDER_NAME)

        if (level.isAtLeast(AdesLevel.T)) {
            val policyId = (tsaPolicy ?: TsaPolicy.TSA_GOST2015_POLICY).policyId
            val timestamped = cms.signerInfos.signers.map {
                tspService.addTspToSigner(it as SignerInformation, certificate, policyId)
            }
            cms = CMSSignedData.replaceSigners(cms, SignerInformationStore(timestamped))
        }

        return cms.encoded
    }

    /**
     * Цепочка из хранилища ключей: PAdES ожидает вложенную цепочку, а не один
     * сертификат подписанта. Если хранилище её не отдало — кладём хотя бы лист.
     */
    private fun certificateChain(keyStore: KeyStoreWrapper): List<X509Certificate> {
        val chain = keyStore.keyStore.getCertificateChain(keyStore.alias)
            ?.filterIsInstance<X509Certificate>()
            .orEmpty()
        return chain.ifEmpty { listOf(keyStore.certificate.x509Certificate) }
    }


    private fun decodePdf(pdf: String): ByteArray = try {
        Base64.getDecoder().decode(pdf)
    } catch (e: IllegalArgumentException) {
        throw ClientException("PDF is not valid base64")
    }

    /**
     * Мост между PDFBox и нашей сборкой CMS. PDFBox требует
     * [SignatureInterface] и допускает наружу только [IOException], поэтому
     * оригинальная ошибка сохраняется в [failure].
     */
    /**
     * Содержимым документной метки служит сам токен RFC 3161 — без обёртки
     * CMS-подписи, в отличие от обычной подписи PDF.
     */
    private inner class DocumentTimestampSigner(
        private val digestOid: String,
        private val policyId: String,
    ) : SignatureInterface {

        var failure: Exception? = null

        @Throws(IOException::class)
        override fun sign(content: InputStream): ByteArray = try {
            tspService.create(content.readBytes(), digestOid, policyId).encoded
        } catch (e: Exception) {
            failure = e
            throw IOException("PAdES document timestamp failed", e)
        }
    }

    private inner class PadesCmsSigner(
        private val keyStore: KeyStoreWrapper,
        private val level: AdesLevel,
        private val tsaPolicy: TsaPolicy?,
    ) : SignatureInterface {

        var failure: Exception? = null

        @Throws(IOException::class)
        override fun sign(content: InputStream): ByteArray = try {
            buildDetachedCms(keyStore, content.readBytes(), level, tsaPolicy)
        } catch (e: Exception) {
            failure = e
            throw IOException("PAdES CMS signing failed", e)
        }
    }

    private companion object {
        private val log = LoggerFactory.getLogger(PadesService::class.java)

        /**
         * Место под токен метки в `/Contents`. GOST-токен НУЦ вместе с
         * сертификатом TSA заметно крупнее типового RSA-токена, поэтому запас
         * взят с большим коэффициентом — не влезет, и PDFBox упадёт на записи.
         */
        private const val TIMESTAMP_RESERVE = 16384
    }
}
