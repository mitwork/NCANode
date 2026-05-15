package kz.ncanode.service

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector
import kz.gov.pki.kalkan.asn1.DERSet
import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.cms.AttributeTable
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.tsp.TSPException
import kz.gov.pki.kalkan.tsp.TimeStampRequestGenerator
import kz.gov.pki.kalkan.tsp.TimeStampResponse
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo
import kz.ncanode.configuration.TspConfiguration
import kz.ncanode.exception.TspException
import kz.ncanode.util.byteToASN1
import kz.ncanode.util.getTspHashAlgorithmByOid
import kz.ncanode.wrapper.CertificateWrapper
import org.apache.http.HttpStatus
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.cert.X509Certificate

@Service
class TspService(
    private val client: CloseableHttpClient,
    private val tspConfiguration: TspConfiguration,
    private val certificateService: CertificateService,
) {

    fun create(data: ByteArray, hashAlg: String, reqPolicy: String): TimeStampToken {
        try {
            val md = MessageDigest.getInstance(hashAlg, KalkanProvider.PROVIDER_NAME)
            md.update(data)
            val hash = md.digest()

            val reqGen = TimeStampRequestGenerator().apply {
                setCertReq(true)
                setReqPolicy(reqPolicy)
            }
            val request = reqGen.generate(hashAlg, hash, generateNonce())
            val reqData = request.encoded

            val maxRetries = maxOf(1, tspConfiguration.retries ?: 1)
            var lastException: RuntimeException? = null

            repeat(maxRetries) {
                try {
                    val response = makeRequest(reqData)
                    response.validate(request)
                    return response.timeStampToken
                } catch (e: RuntimeException) {
                    lastException = e
                }
            }

            throw lastException ?: TspException("TSP creation failed without exception")
        } catch (e: GeneralSecurityException) {
            log.error("TSP creation failure.", e)
            throw TspException("TSP creation failure", e)
        } catch (e: IOException) {
            log.error("TSP creation failure.", e)
            throw TspException("TSP creation failure", e)
        } catch (e: TSPException) {
            log.error("TSP creation failure.", e)
            throw TspException("TSP creation failure", e)
        }
    }

    /**
     * Полная криптографическая проверка TSP-токена в режиме CAdES-T:
     *  1) подпись TSA на токене валидна;
     *  2) messageImprint токена совпадает с хэшем подписи внешнего подписанта
     *     (т.е. метка действительно проставлена для этой подписи, а не подложена);
     *  3) сертификат TSA содержит EKU id-kp-timeStamping (RFC 3161);
     *  4) сертификат TSA и его эмитент валидны на момент genTime метки
     *     (а не на текущую дату — иначе протухший TSA сломал бы все архивные подписи).
     *
     * Возвращает [TimeStampTokenInfo], только если ВСЕ проверки прошли —
     * иначе `null` (с предупреждением в логе). Никаких исключений наружу не
     * пробрасывает: некорректный TSP не должен валить верификацию внешней
     * подписи, он лишь не даёт права использовать genTime как
     * "момент истины".
     */
    fun verify(
        tspCms: CMSSignedData,
        outerSignerSignature: ByteArray,
        checkOcsp: Boolean,
        checkCrl: Boolean,
    ): TimeStampTokenInfo? {
        try {
            val tspSignersCol = tspCms.signerInfos.signers
            if (tspSignersCol.isEmpty()) {
                log.warn("TSP token has no signers")
                return null
            }
            val tspSigner = tspSignersCol.iterator().next() as SignerInformation

            val tsaCertStore = tspCms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            val tsaCerts = tsaCertStore.getCertificates(tspSigner.sid)
            if (tsaCerts.isEmpty()) {
                log.warn("TSP token does not embed TSA certificate")
                return null
            }
            val tsaCert = CertificateWrapper(tsaCerts.iterator().next() as X509Certificate)

            // 1) Подпись TSA на токене. Используем ручную верификацию вместо
            // TimeStampToken.validate(...) — последний жёстко проверяет срок
            // действия TSA на текущий момент, что ломает архивные метки.
            if (!tspSigner.verify(tsaCert.publicKey, KalkanProvider.PROVIDER_NAME)) {
                log.warn("TSP token signature verification failed")
                return null
            }

            val tspi = TimeStampToken(tspCms).timeStampInfo

            // 2) Импринт TSP-токена должен быть хэшем именно подписи внешнего
            // подписанта (RFC 3161, CAdES-T). Алгоритм берём ровно тот, что
            // объявлен в самой метке — OID отдаём провайдеру напрямую, чтобы
            // не зависеть от неполных маппингов OID→имя в KalkanUtil
            // (там, например, getTspHashAlgorithmByOid возвращает старый
            // GOST 34.311 для любого не-RSA, что ломает GOST 2015-метки).
            val imprintAlgOid = tspi.messageImprintAlgOID
            val md = try {
                MessageDigest.getInstance(imprintAlgOid, KalkanProvider.PROVIDER_NAME)
            } catch (e: NoSuchAlgorithmException) {
                log.warn("Unsupported TSP imprint algorithm OID: {}", imprintAlgOid)
                return null
            }
            val expectedImprint = md.digest(outerSignerSignature)
            if (!expectedImprint.contentEquals(tspi.messageImprintDigest)) {
                log.warn(
                    "TSP messageImprint does not match outer signer signature (alg OID {})",
                    imprintAlgOid,
                )
                return null
            }

            // 3) EKU id-kp-timeStamping — обязателен для TSA по RFC 3161.
            val eku = tsaCert.extendedKeyUsage
            if (EKU_TIME_STAMPING_OID !in eku) {
                log.warn("TSA certificate does not declare id-kp-timeStamping EKU")
                return null
            }

            // 4) TSA-цепочка валидна на genTime.
            val genTime = tspi.genTime
            if (genTime == null) {
                log.warn("TSP token has no genTime")
                return null
            }

            certificateService.attachValidationData(tsaCert, checkOcsp, checkCrl)
            if (!tsaCert.isValid(genTime, checkOcsp, checkCrl)) {
                log.warn("TSA certificate is not valid at TSP genTime {}", genTime)
                return null
            }

            return tspi
        } catch (e: Exception) {
            log.warn("TSP verification error: {}", e.message, e)
            return null
        }
    }

    fun info(data: CMSSignedData): TimeStampTokenInfo? = try {
        val tspt = TimeStampToken(data)
        val certs = data.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
        val certCollection = certs.getCertificates(tspt.sid)
        val cert = certCollection.firstOrNull() as? X509Certificate
        if (cert == null) {
            null
        } else {
            tspt.validate(cert, KalkanProvider.PROVIDER_NAME)
            tspt.timeStampInfo
        }
    } catch (e: Exception) {
        log.error("TSP verification error.", e)
        null
    }

    fun generateNonce(): BigInteger = BigInteger.valueOf(System.currentTimeMillis())

    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, TSPException::class, IOException::class)
    fun addTspToSigner(signer: SignerInformation, cert: X509Certificate, useTsaPolicy: String): SignerInformation {
        val unsignedAttributes = signer.unsignedAttributes
        val vector = unsignedAttributes?.toASN1EncodableVector() ?: ASN1EncodableVector()

        val tsp = create(signer.signature, getTspHashAlgorithmByOid(cert.sigAlgOID), useTsaPolicy)
        val ts = tsp.encoded
        val signatureTimeStamp = Attribute(
            PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
            DERSet(byteToASN1(ts)),
        )
        vector.add(signatureTimeStamp)

        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(vector))
    }

    private fun makeRequest(request: ByteArray): TimeStampResponse {
        val url = tspConfiguration.parsedUrl
        if (url == null) {
            log.error("Invalid TSP url")
            throw TspException("Invalid tsp url")
        }

        val httpPost = HttpPost(url.toString()).apply {
            setHeader("Content-Type", "application/timestamp-query")
            entity = ByteArrayEntity(request)
        }

        try {
            client.execute(httpPost).use { response ->
                val statusCode = response.statusLine.statusCode
                if (statusCode != HttpStatus.SC_OK) {
                    log.error("Invalid TSP response status: {}", statusCode)
                    throw TspException("Invalid TSP response status: $statusCode")
                }
                return TimeStampResponse(response.entity.content)
            }
        } catch (e: IOException) {
            throw TspException("TSP request failure.", e)
        } catch (e: TSPException) {
            throw TspException("TSP request failure.", e)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(TspService::class.java)

        /**
         * OID id-kp-timeStamping (RFC 3161): сертификат TSA должен содержать его в EKU.
         */
        private const val EKU_TIME_STAMPING_OID = "1.3.6.1.5.5.7.3.8"
    }
}
