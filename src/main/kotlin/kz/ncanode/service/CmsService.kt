package kz.ncanode.service

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSException
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.gov.pki.kalkan.util.encoders.Hex
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.cms.CmsSignerInfo
import kz.ncanode.dto.request.CmsCreateBatchRequest
import kz.ncanode.dto.request.CmsCreateRequest
import kz.ncanode.dto.request.CmsExtractBatchRequest
import kz.ncanode.dto.request.CmsVerifyBatchRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.response.CmsBatchResponse
import kz.ncanode.dto.response.CmsDataResponse
import kz.ncanode.dto.response.CmsExtractBatchResponse
import kz.ncanode.dto.response.CmsResponse
import kz.ncanode.dto.response.CmsVerificationBatchResponse
import kz.ncanode.dto.response.CmsVerificationResponse
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.dto.tsp.TspInfo
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getHashingAlgorithmByOID
import kz.ncanode.util.mapPartial
import kz.ncanode.util.warnIfRevocationDisabled
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.Signature
import java.security.cert.CertStore
import java.security.cert.CertStoreException
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

@Service
class CmsService(
    private val kalkanWrapper: KalkanWrapper,
    private val tspService: TspService,
    private val certificateService: CertificateService,
) {

    /**
     * Создаёт подписанный CMS.
     */
    fun create(cmsCreateRequest: CmsCreateRequest): CmsResponse {
        try {
            // data обязателен для create (в отличие от addSigners, где он опционален
            // для attached-CMS). Без явной проверки null-data уходил в Base64.decode(null)
            // → NPE → 500 message:null вместо честного 400.
            val dataBase64 = cmsCreateRequest.data
                ?: throw ClientException("Data argument not specified")
            val generator = CMSSignedDataGenerator()
            val data = Base64.getDecoder().decode(dataBase64)
            val cmsData = CMSProcessableByteArray(data)
            val certificates = mutableListOf<X509Certificate>()

            addSignersToCmsGenerator(generator, data, certificates, cmsCreateRequest.signers)

            val signed = generateSignedCms(
                generator, cmsData, certificates,
                detached = cmsCreateRequest.isDetached,
                withTsp = cmsCreateRequest.isWithTsp,
                tsaPolicy = cmsCreateRequest.tsaPolicy,
            )

            return CmsResponse(cms = Base64.getEncoder().encodeToString(signed.encoded))
        } catch (e: ApplicationException) {
            // Намеренный 400 (напр. null data) не заворачиваем в 500.
            throw e
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Batch-создание CMS. На каждый элемент [CmsCreateBatchRequest.data]
     * создаётся отдельный CMS общим набором signer'ов с одинаковыми
     * TSP/detached флагами. Partial-response: ошибка на N-м data
     * не валит остальные (issue malikzh/NCANode#212).
     */
    fun createBatch(request: CmsCreateBatchRequest): CmsBatchResponse {
        val items = request.data.mapPartial({ status, message ->
            CmsBatchResponse.Item(status = status, message = message)
        }) { data ->
            val itemRequest = CmsCreateRequest().apply {
                this.data = data
                this.signers = request.signers
                this.isWithTsp = request.isWithTsp
                this.tsaPolicy = request.tsaPolicy
                this.isDetached = request.isDetached
            }
            CmsBatchResponse.Item(cms = create(itemRequest).cms)
        }
        return CmsBatchResponse(results = items)
    }

    /**
     * Добавляет подписи уже к существующему CMS.
     */
    fun addSigners(cmsCreateRequest: CmsCreateRequest): CmsResponse {
        try {
            val cmsBase64 = cmsCreateRequest.cms
            if (cmsBase64.isNullOrEmpty()) {
                throw ClientException("CMS argument not specified")
            }

            val decodedCms = Base64.getDecoder().decode(cmsBase64)
            var cms = CMSSignedData(decodedCms)
            val decodedData: ByteArray

            if (cms.signedContent == null) {
                val dataBase64 = cmsCreateRequest.data
                if (dataBase64.isNullOrEmpty()) {
                    throw ClientException("Data must be specifieed for detached CMS")
                }
                decodedData = Base64.getDecoder().decode(dataBase64)
                cms = CMSSignedData(CMSProcessableByteArray(decodedData), decodedCms)
            } else {
                decodedData = ByteArrayOutputStream().use { out ->
                    cms.signedContent.write(out)
                    out.toByteArray()
                }
            }

            val cmsData = CMSProcessableByteArray(decodedData)

            val generator = CMSSignedDataGenerator().apply {
                addSigners(cms.signerInfos)
            }

            val certificates = getCertificatesFromCmsSignedData(cms)
            addSignersToCmsGenerator(generator, decodedData, certificates, cmsCreateRequest.signers)

            val signed = generateSignedCms(
                generator, cmsData, certificates,
                detached = cmsCreateRequest.isDetached,
                withTsp = cmsCreateRequest.isWithTsp,
                tsaPolicy = cmsCreateRequest.tsaPolicy,
                // Нельзя перезатирать TSP у предыдущих подписантов: старым метку
                // не ставим, новым ставим.
                skipTspFor = { signer -> isSignerSameAsPrevious(signer, cms) },
            )

            return CmsResponse(cms = Base64.getEncoder().encodeToString(signed.encoded))
        } catch (e: ApplicationException) {
            // Намеренно классифицированные ошибки (400 «CMS/data not specified»)
            // не заворачиваем в 500 — раньше свой же ClientException глотался.
            throw e
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Собирает подписанный CMS: chainStore из [certificates], generate, и (если
     * [withTsp]) добавляет TSP-метку каждому подписанту, для которого
     * [skipTspFor] = false. Общая часть [create] и [addSigners]; TSP индексируется
     * по позиции подписанта в [certificates] (создание/добавление сохраняют
     * порядок cert ↔ signer).
     */
    private fun generateSignedCms(
        generator: CMSSignedDataGenerator,
        cmsData: CMSProcessableByteArray,
        certificates: List<X509Certificate>,
        detached: Boolean,
        withTsp: Boolean,
        tsaPolicy: TsaPolicy?,
        skipTspFor: (SignerInformation) -> Boolean = { false },
    ): CMSSignedData {
        val chainStore = CertStore.getInstance(
            "Collection",
            // Уникальные сертификаты: при re-sign они могут дублироваться.
            CollectionCertStoreParameters(certificates.distinct()),
            KalkanProvider.PROVIDER_NAME,
        )
        generator.addCertificatesAndCRLs(chainStore)
        var signed = generator.generate(cmsData, !detached, KalkanProvider.PROVIDER_NAME)

        if (withTsp) {
            val useTsaPolicy = tsaPolicy?.policyId ?: TsaPolicy.TSA_GOST2015_POLICY.policyId
            val updated = signed.signerInfos.signers.mapIndexed { i, signerObj ->
                val signer = signerObj as SignerInformation
                if (skipTspFor(signer)) signer
                else tspService.addTspToSigner(signer, certificates[i], useTsaPolicy)
            }
            signed = CMSSignedData.replaceSigners(signed, SignerInformationStore(updated))
        }
        return signed
    }

    private fun isSignerSameAsPrevious(signer: SignerInformation, cms: CMSSignedData): Boolean =
        cms.signerInfos.signers.any { (it as SignerInformation).sid == signer.sid }

    /**
     * Проверяет подписанный CMS.
     */
    fun verify(
        signedCms: String,
        detachedData: String?,
        checkOcsp: Boolean,
        checkCrl: Boolean,
        /**
         * Вызывается для каждого сертификата подписанта до проверки. Позволяет
         * заранее прикрепить вердикты по вшитому в подпись материалу (уровень
         * LT): дальше `attachValidationData` в сеть за ними уже не пойдёт.
         * По умолчанию ничего не делает — поведение прежних вызовов не меняется.
         */
        prepare: (CertificateWrapper) -> Unit = {},
    ): CmsVerificationResponse {
        warnIfRevocationDisabled(checkOcsp, checkCrl)
        try {
            val cms = parseCms(signedCms, detachedData)
            val certStore = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            val signerCerts = collectSignerCertificates(cms, certStore)

            // Batch-prefetch: параллельный OCSP + последовательный CRL/issuer
            // для всех cert'ов всех подписантов сразу (для CMS с N подписантами —
            // почти N-кратное ускорение при NCANODE_OCSP_PARALLEL).
            signerCerts.values.flatten().forEach(prepare)

            if (checkOcsp || checkCrl) {
                certificateService.prefetchValidationData(signerCerts.values.flatten(), checkOcsp, checkCrl)
            }

            // RFC 5652 §5.1: SignedData без единого SignerInfo ничего не
            // удостоверяет. Без этой проверки CMS с пустым signerInfos прошёл
            // бы цикл ниже вхолостую и вернул valid=true — ложно-положительный
            // вердикт «документ валидно подписан» при отсутствии подписей.
            if (signerCerts.isEmpty()) {
                return CmsVerificationResponse(valid = false, signers = emptyList())
            }

            val signers = mutableListOf<CmsSignerInfo>()
            var valid = true
            val currentDate = certificateService.getCurrentDate()

            for ((signer, certs) in signerCerts) {
                val result = verifySigner(signer, certs, checkOcsp, checkCrl, currentDate)
                if (!result.valid) valid = false
                signers.add(result.info)
            }

            return CmsVerificationResponse(valid = valid, signers = signers)
        } catch (e: ApplicationException) {
            throw e
        } catch (e: CMSException) {
            // Битая CMS-структура — ошибка входа клиента.
            throw ClientException(e.message, e)
        } catch (e: IllegalArgumentException) {
            // Невалидный base64 в signedCms/detachedData — тоже клиентский вход.
            throw ClientException(e.message, e)
        } catch (e: Exception) {
            // Всё остальное (сбой OCSP/CA-цепочки, NPE в Kalkan) — ВНУТРЕННЯЯ
            // ошибка: 500, а не 400. Раньше всё маппилось в ClientException,
            // и клиент думал, что его CMS битый, при упавшей инфраструктуре.
            throw ServerException(e.message, e)
        }
    }

    /** Парсит CMS; для detached (без signedContent) досоединяет [detachedData]. */
    private fun parseCms(signedCms: String, detachedData: String?): CMSSignedData {
        val cms = CMSSignedData(Base64.getDecoder().decode(signedCms.toByteArray(StandardCharsets.UTF_8)))
        if (detachedData != null && cms.signedContent == null) {
            return CMSSignedData(
                CMSProcessableByteArray(Base64.getDecoder().decode(detachedData)),
                Base64.getDecoder().decode(signedCms),
            )
        }
        return cms
    }

    /**
     * Pre-collect signer → его сертификаты. Нужно, чтобы prefetch OCSP/CRL сделать
     * одним батчем для всех cert'ов (параллельный OCSP), а не последовательно
     * per-signer внутри цикла верификации.
     */
    private fun collectSignerCertificates(
        cms: CMSSignedData,
        certStore: CertStore,
    ): LinkedHashMap<SignerInformation, List<CertificateWrapper>> {
        val result = LinkedHashMap<SignerInformation, List<CertificateWrapper>>()
        for (signerObj in cms.signerInfos.signers) {
            val s = signerObj as SignerInformation
            result[s] = certStore.getCertificates(s.sid).map { CertificateWrapper(it as X509Certificate) }
        }
        return result
    }

    private data class SignerVerification(val valid: Boolean, val info: CmsSignerInfo)

    /**
     * Проверка одного подписанта: TSP-метка (CAdES-T, задаёт validationDate),
     * криптопроверка подписи и валидность каждого cert'а. Возвращает вклад в
     * общий `valid` + [CmsSignerInfo].
     */
    private fun verifySigner(
        signer: SignerInformation,
        certs: List<CertificateWrapper>,
        checkOcsp: Boolean,
        checkCrl: Boolean,
        currentDate: Date,
    ): SignerVerification {
        var valid = true
        var tspInfo: TspInfo? = null
        // Время проверки срока действия cert'а подписанта. При валидной TSP-метке —
        // её genTime (CAdES-T): подпись валидна, если cert был валиден на момент
        // метки, даже если к моменту верификации истёк.
        var validationDate = currentDate

        if (tspService.hasTimestampAttribute(signer)) {
            // Строгая проверка TSP (подпись TSA, messageImprint, EKU, валидность
            // цепочки TSA на genTime). Метку добавил подписант — если её не
            // удалось извлечь (нет ровно одного токена) или она не прошла проверку,
            // откатываться на currentDate нельзя: вся подпись невалидна (CAdES-T
            // strict).
            val tspCms = tspService.extractTimestampToken(signer)
            val tspi = tspCms?.let { tspService.verify(it, signer.signature, checkOcsp, checkCrl) }
            if (tspi != null) {
                try {
                    tspInfo = TspInfo(
                        serialNumber = String(Hex.encode(tspi.serialNumber.toByteArray())),
                        genTime = tspi.genTime,
                        policy = tspi.policy,
                        tsa = tspi.tsa?.toString(),
                        tspHashAlgorithm = getHashingAlgorithmByOID(tspi.messageImprintAlgOID),
                        hash = String(Hex.encode(tspi.messageImprintDigest)),
                    )
                    if (tspi.genTime != null) {
                        validationDate = tspi.genTime
                    }
                } catch (e: Exception) {
                    log.warn(e.message, e)
                }
            } else {
                log.warn("Signer has TSP timestamp attribute but TSP verification failed — marking CMS as invalid")
                valid = false
            }
        }

        // RFC 5652 §5.6: подпись обязана быть криптопроверена. Нет cert'а для
        // signer.sid → цикл ниже пуст → signer.verify() не вызовется. Это провал
        // верификации (иначе подписант без вложенного cert'а молча = ОК).
        if (certs.isEmpty()) {
            log.warn(
                "CMS signer {} has no matching certificate in the embedded store — signature cannot be verified",
                signer.sid,
            )
            valid = false
        }

        val certificateInfos = mutableListOf<CertificateInfo>()
        for (cert in certs) {
            // attachValidationData идемпотентен: prefetch уже сделал тяжёлую часть
            // (OCSP параллельно, CRL с кэшем), здесь только issuer если он null.
            certificateService.attachValidationData(cert, checkOcsp, checkCrl)
            if (!signer.verify(cert.publicKey, KalkanProvider.PROVIDER_NAME)
                || !cert.isValid(validationDate, checkOcsp, checkCrl)
            ) {
                valid = false
            }
            certificateInfos.add(cert.toCertificateInfo(validationDate, checkOcsp, checkCrl))
        }

        return SignerVerification(
            valid,
            CmsSignerInfo(valid = valid, certificates = certificateInfos, tsp = tspInfo),
        )
    }

    /**
     * Batch-верификация: каждая пара (cms, data?) проверяется независимо
     * с общими revocation-флагами. На исключение — item возвращается с
     * `valid=false` и status/message; остальные продолжают.
     */
    fun verifyBatch(request: CmsVerifyBatchRequest): CmsVerificationBatchResponse {
        val checkOcsp = request.checkOcsp
        val checkCrl = request.checkCrl
        val items = request.items.mapPartial({ status, message ->
            CmsVerificationResponse(valid = false, status = status, message = message)
        }) { item ->
            verify(item.cms, item.data, checkOcsp, checkCrl)
        }
        return CmsVerificationBatchResponse(results = items)
    }

    /**
     * Batch-извлечение payload'а из массива CMS. Detached-CMS (без
     * signedContent) корректно отметится как 500/ClientException
     * без падения остальных.
     */
    fun extractBatch(request: CmsExtractBatchRequest): CmsExtractBatchResponse {
        val items = request.cms.mapPartial({ status, message ->
            CmsExtractBatchResponse.Item(status = status, message = message)
        }) { cms ->
            CmsExtractBatchResponse.Item(data = extract(cms).data)
        }
        return CmsExtractBatchResponse(results = items)
    }

    /**
     * Извлекает данные из CMS если они есть.
     */
    fun extract(signedCms: String): CmsDataResponse {
        try {
            val cms = CMSSignedData(Base64.getDecoder().decode(signedCms))
            val content = cms.signedContent ?: throw ClientException("CMS doesn't have signed content")

            return ByteArrayOutputStream().use { out ->
                content.write(out)
                CmsDataResponse(data = Base64.getEncoder().encodeToString(out.toByteArray()))
            }
        } catch (e: CMSException) {
            throw ServerException(e.message, e)
        } catch (e: IOException) {
            throw ServerException(e.message, e)
        }
    }

    @Throws(CMSException::class, CertStoreException::class)
    private fun getCertificatesFromCmsSignedData(cms: CMSSignedData): MutableList<X509Certificate> {
        val certs = mutableListOf<X509Certificate>()
        val clientCerts = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)

        for (signerObj in cms.signerInfos.signers) {
            val signer = signerObj as SignerInformation
            val certCollection = clientCerts.getCertificates(signer.sid)
            for (certificate in certCollection) {
                certs.add(certificate as X509Certificate)
            }
        }
        return certs
    }

    private fun addSignersToCmsGenerator(
        generator: CMSSignedDataGenerator,
        decodedData: ByteArray,
        certificates: MutableList<X509Certificate>,
        signers: List<SignerRequest>,
    ) {
        try {
            for (ks in kalkanWrapper.read(signers)) {
                val cert = ks.certificate
                val privateKey = ks.privateKey
                val x509 = cert.x509Certificate

                val sig = Signature.getInstance(x509.sigAlgName, kalkanWrapper.kalkanProvider)
                sig.initSign(privateKey)
                sig.update(decodedData)

                generator.addSigner(privateKey, x509, getDigestAlgorithmOidBYSignAlgorithmOid(x509.sigAlgOID))
                certificates.add(x509)
            }
        } catch (e: ApplicationException) {
            // ClientException от KalkanWrapper.read (плохой пароль p12) — 400,
            // не заворачиваем в 500 (иначе /cms/sign отдавал бы 500 на плохой ключ).
            throw e
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(CmsService::class.java)
    }
}
