package kz.ncanode.service

import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSException
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.gov.pki.kalkan.util.encoders.Hex
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.certificate.CertificateRevocation
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
import org.springframework.http.HttpStatus
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getHashingAlgorithmByOID
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
import java.util.Vector

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
            val generator = CMSSignedDataGenerator()
            val data = Base64.getDecoder().decode(cmsCreateRequest.data)
            val cmsData = CMSProcessableByteArray(data)
            val certificates = mutableListOf<X509Certificate>()

            addSignersToCmsGenerator(generator, data, certificates, cmsCreateRequest.signers)

            val chainStore = CertStore.getInstance(
                "Collection",
                // если происходит повторная подпись, сертификаты могут дублироваться.
                // добавим в chainStore только уникальные сертификаты.
                CollectionCertStoreParameters(certificates),
                KalkanProvider.PROVIDER_NAME,
            )

            generator.addCertificatesAndCRLs(chainStore)
            var signed = generator.generate(cmsData, !cmsCreateRequest.isDetached, KalkanProvider.PROVIDER_NAME)

            // TSP
            if (cmsCreateRequest.isWithTsp) {
                val useTsaPolicy = cmsCreateRequest.tsaPolicy?.policyId ?: TsaPolicy.TSA_GOST2015_POLICY.policyId

                val updated = signed.signerInfos.signers.mapIndexed { i, signerObj ->
                    val cert = certificates[i]
                    tspService.addTspToSigner(signerObj as SignerInformation, cert, useTsaPolicy)
                }

                signed = CMSSignedData.replaceSigners(signed, SignerInformationStore(updated))
            }

            return CmsResponse(cms = Base64.getEncoder().encodeToString(signed.encoded))
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
        val items = request.data.map { data ->
            try {
                val itemRequest = CmsCreateRequest().apply {
                    this.data = data
                    this.signers = request.signers
                    this.isWithTsp = request.isWithTsp
                    this.tsaPolicy = request.tsaPolicy
                    this.isDetached = request.isDetached
                }
                val response = create(itemRequest)
                CmsBatchResponse.Item(cms = response.cms)
            } catch (e: ApplicationException) {
                CmsBatchResponse.Item(status = e.status, message = e.message)
            } catch (e: Exception) {
                CmsBatchResponse.Item(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    message = e.message,
                )
            }
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

            val chainStore = CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(certificates.distinct()),
                KalkanProvider.PROVIDER_NAME,
            )
            generator.addCertificatesAndCRLs(chainStore)
            var signed = generator.generate(cmsData, !cmsCreateRequest.isDetached, KalkanProvider.PROVIDER_NAME)

            // TSP
            if (cmsCreateRequest.isWithTsp) {
                val useTsaPolicy = cmsCreateRequest.tsaPolicy?.policyId ?: TsaPolicy.TSA_GOST2015_POLICY.policyId

                val updated = signed.signerInfos.signers.mapIndexed { i, signerObj ->
                    val signer = signerObj as SignerInformation
                    val cert = certificates[i]
                    // Нельзя перезатирать TSP у предыдущих подписантов: старых
                    // оставляем без изменений, новым ставим TSP.
                    if (isSignerSameAsPrevious(signer, cms)) signer
                    else tspService.addTspToSigner(signer, cert, useTsaPolicy)
                }

                signed = CMSSignedData.replaceSigners(signed, SignerInformationStore(updated))
            }

            return CmsResponse(cms = Base64.getEncoder().encodeToString(signed.encoded))
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
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
    ): CmsVerificationResponse {
        try {
            var cms = CMSSignedData(Base64.getDecoder().decode(signedCms.toByteArray(StandardCharsets.UTF_8)))

            if (detachedData != null && cms.signedContent == null) {
                cms = CMSSignedData(
                    CMSProcessableByteArray(Base64.getDecoder().decode(detachedData)),
                    Base64.getDecoder().decode(signedCms),
                )
            }

            val certStore = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)

            // Pre-collect signers + их сертификаты в Map.
            // Это нужно чтобы prefetch валидационных данных (OCSP/CRL) сделать
            // одним батчем для всех cert'ов параллельно, а не последовательно
            // внутри цикла per-signer. Для CMS с N подписантами OCSP-запросы
            // уйдут параллельно — ускорение почти N-кратное (при включённом
            // NCANODE_OCSP_PARALLEL).
            val signerCerts = LinkedHashMap<SignerInformation, List<CertificateWrapper>>()
            for (signerObj in cms.signerInfos.signers) {
                val s = signerObj as SignerInformation
                val certCollection = certStore.getCertificates(s.sid)
                val wrapped = certCollection.map { CertificateWrapper(it as X509Certificate) }
                signerCerts[s] = wrapped
            }

            // Batch-prefetch: параллельный OCSP + последовательный CRL/issuer
            // для всех cert'ов всех подписантов сразу.
            if (checkOcsp || checkCrl) {
                val allCerts = signerCerts.values.flatten()
                certificateService.prefetchValidationData(allCerts, checkOcsp, checkCrl)
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
                var tspInfo: TspInfo? = null

                // Время, на которое проверяется срок действия сертификата подписанта.
                // При наличии валидной TSP-метки используем её genTime (CAdES-T):
                // подпись считается валидной, если сертификат был валиден в момент
                // постановки метки, даже если к моменту верификации он истёк.
                var validationDate = currentDate

                val unsignedAttrs = signer.unsignedAttributes?.toHashtable()
                if (unsignedAttrs != null && unsignedAttrs.containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
                    val attr = when (val obj = unsignedAttrs[PKCSObjectIdentifiers.id_aa_signatureTimeStampToken]) {
                        is Vector<*> -> obj[0] as Attribute
                        else -> obj as Attribute
                    }

                    if (attr.attrValues.size() != 1) {
                        throw Exception("Too many TSP tokens")
                    }

                    val tspCms = CMSSignedData(attr.attrValues.getObjectAt(0).derObject.encoded)

                    // Строгая проверка TSP (подпись TSA, messageImprint, EKU,
                    // валидность цепочки TSA на genTime). Подписант явно добавил
                    // TSP-метку — это его заявление "верьте этому времени"; если
                    // метка не проходит проверку, мы не имеем права молча
                    // откатиться на currentDate: либо метка подделана, либо TSA
                    // не доверенна — в обоих случаях вся подпись считается
                    // невалидной (CAdES-T strict).
                    val tspi = tspService.verify(tspCms, signer.signature, checkOcsp, checkCrl)

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

                // RFC 5652 §5.6: подпись подписанта обязана быть криптографически
                // проверена. Если для signer.sid не нашлось сертификата в CMS,
                // проверять нечем — цикл по certs ниже не выполнится, signer.verify()
                // не вызовется. Это не «успех по умолчанию», а провал верификации:
                // иначе подписант, чей cert не вложен, молча засчитывался бы как ОК.
                if (certs.isEmpty()) {
                    log.warn(
                        "CMS signer {} has no matching certificate in the embedded store — signature cannot be verified",
                        signer.sid,
                    )
                    valid = false
                }

                val certificateInfos = mutableListOf<CertificateInfo>()
                for (cert in certs) {
                    // attachValidationData идемпотентен: prefetch уже сделал
                    // тяжёлую часть (OCSP параллельно, CRL с кэшем), здесь
                    // только выставится issuer если он null.
                    certificateService.attachValidationData(cert, checkOcsp, checkCrl)

                    if (!signer.verify(cert.publicKey, KalkanProvider.PROVIDER_NAME)
                        || !cert.isValid(validationDate, checkOcsp, checkCrl)
                    ) {
                        valid = false
                    }

                    certificateInfos.add(cert.toCertificateInfo(validationDate, checkOcsp, checkCrl))
                }

                signers.add(CmsSignerInfo(certificates = certificateInfos, tsp = tspInfo))
            }

            return CmsVerificationResponse(valid = valid, signers = signers)
        } catch (e: Exception) {
            throw ClientException(e.message, e)
        }
    }

    /**
     * Batch-верификация: каждая пара (cms, data?) проверяется независимо
     * с общими revocation-флагами. На исключение — item возвращается с
     * `valid=false` и status/message; остальные продолжают.
     */
    fun verifyBatch(request: CmsVerifyBatchRequest): CmsVerificationBatchResponse {
        val checkOcsp = CertificateRevocation.OCSP in request.revocationCheck
        val checkCrl = CertificateRevocation.CRL in request.revocationCheck
        val items = request.items.map { item ->
            try {
                verify(item.cms, item.data, checkOcsp, checkCrl)
            } catch (e: ApplicationException) {
                CmsVerificationResponse(valid = false, status = e.status, message = e.message)
            } catch (e: Exception) {
                CmsVerificationResponse(
                    valid = false,
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    message = e.message,
                )
            }
        }
        return CmsVerificationBatchResponse(results = items)
    }

    /**
     * Batch-извлечение payload'а из массива CMS. Detached-CMS (без
     * signedContent) корректно отметится как 500/ClientException
     * без падения остальных.
     */
    fun extractBatch(request: CmsExtractBatchRequest): CmsExtractBatchResponse {
        val items = request.cms.map { cms ->
            try {
                val response = extract(cms)
                CmsExtractBatchResponse.Item(data = response.data)
            } catch (e: ApplicationException) {
                CmsExtractBatchResponse.Item(status = e.status, message = e.message)
            } catch (e: Exception) {
                CmsExtractBatchResponse.Item(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    message = e.message,
                )
            }
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
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(CmsService::class.java)
    }
}
