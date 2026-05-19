package kz.ncanode.service

import kz.gov.pki.kalkan.asn1.ASN1InputStream
import kz.gov.pki.kalkan.asn1.DEROctetString
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers
import kz.gov.pki.kalkan.asn1.x509.X509Extension
import kz.gov.pki.kalkan.asn1.x509.X509Extensions
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp
import kz.gov.pki.kalkan.ocsp.CertificateID
import kz.gov.pki.kalkan.ocsp.OCSPException
import kz.gov.pki.kalkan.ocsp.OCSPReq
import kz.gov.pki.kalkan.ocsp.OCSPReqGenerator
import kz.gov.pki.kalkan.ocsp.OCSPResp
import kz.gov.pki.kalkan.ocsp.RevokedStatus
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.configuration.OcspConfiguration
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.wrapper.CertificateWrapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.IOException
import java.math.BigInteger
import java.net.URI
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.GeneralSecurityException
import java.security.NoSuchProviderException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Hashtable

/**
 * Сервис для работы с сервером OCSP (Проверка сертификатов на отозванность).
 */
@Service
class OcspService(
    private val kalkanProvider: KalkanProvider,
    private val ocspConfiguration: OcspConfiguration,
    private val client: HttpClient,
    private val httpClientConfiguration: HttpClientConfiguration,
) {

    /**
     * Выполняет запрос на OCSP серверы и возвращает статус для каждого URL.
     *
     * URL'ы определяются по такому правилу:
     *  1) Если в сертификате есть extension `authorityInfoAccess` с
     *     `id-ad-ocsp` (RFC 5280 §4.2.2.1) — используются URL'ы оттуда.
     *     Cert сам говорит, какой responder обслуживает его revocation.
     *  2) Если AIA отсутствует — fallback на `NCANODE_OCSP_URL` из конфига.
     *
     * URL'ы фильтруются по схеме: разрешаются только http/https
     * (defense-in-depth против SSRF на file:// и т.п.).
     */
    fun verify(cert: CertificateWrapper, issuer: CertificateWrapper?): List<OcspStatus> {
        if (issuer == null) {
            return listOf(
                OcspStatus(
                    result = OcspResult.UNKNOWN,
                    message = "Cannot find root certificate in NCANode. Try add it using NCANODE_CA_URL variable.",
                )
            )
        }

        val statuses = mutableListOf<OcspStatus>()
        for (ocspUrl in resolveOcspUrls(cert)) {
            val url = ocspUrl.toString()
            try {
                val nonce = generateOcspNonce()
                val request = buildOcspRequest(cert.x509Certificate.serialNumber, issuer.x509Certificate, nonce)

                val response = makeRequest(url, request.encoded)
                val status = processOcspResponse(response, nonce, issuer)
                statuses.add(status.copy(url = url))
            } catch (e: IOException) {
                statuses.add(unknownStatus(url, e.message))
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                statuses.add(unknownStatus(url, e.message))
            } catch (e: OCSPException) {
                statuses.add(unknownStatus(url, e.message))
            } catch (e: GeneralSecurityException) {
                statuses.add(unknownStatus(url, e.message))
            }
        }

        return statuses
    }

    /**
     * Определяет, какие OCSP-URL'ы использовать для проверки этого cert'а.
     * Приоритет: AIA-extension cert'а → config fallback.
     */
    private fun resolveOcspUrls(cert: CertificateWrapper): List<URL> {
        val aiaUrls = cert.ocspUrls.filter { isAllowedScheme(it) }
        if (aiaUrls.isNotEmpty()) {
            log.debug("Using OCSP URLs from cert AIA: {}", aiaUrls)
            return aiaUrls
        }

        val configUrls = ocspConfiguration.urlList.values.filter { isAllowedScheme(it) }
        if (configUrls.isNotEmpty()) {
            log.debug("Cert has no AIA OCSP URLs, falling back to {} configured URL(s)", configUrls.size)
        }
        return configUrls
    }

    private fun isAllowedScheme(url: URL): Boolean {
        val scheme = url.protocol
        val ok = scheme.equals("http", ignoreCase = true) || scheme.equals("https", ignoreCase = true)
        if (!ok) {
            log.warn("Refusing OCSP URL with disallowed scheme: {}", url)
        }
        return ok
    }

    @Throws(OCSPException::class)
    private fun buildOcspRequest(serialNumber: BigInteger, issuer: X509Certificate, nonce: ByteArray): OCSPReq {
        val gen = OCSPReqGenerator()
        val certId = CertificateID(CertificateID.HASH_SHA256, issuer, serialNumber, kalkanProvider.name)
        gen.addRequest(certId)
        val ext = Hashtable<Any, Any>()
        ext[OCSPObjectIdentifiers.id_pkix_ocsp_nonce] =
            object : X509Extension(false, DEROctetString(DEROctetString(nonce))) {}
        gen.setRequestExtensions(X509Extensions(ext))
        return gen.generate()
    }

    fun generateOcspNonce(): ByteArray {
        val nonce = ByteArray(NONCE_LENGTH)
        SecureRandom().nextBytes(nonce)
        return nonce
    }

    /**
     * Парсит и верифицирует OCSP-ответ. Возвращает финальный статус
     * (ACTIVE / REVOKED / UNKNOWN). Защищает от MITM-атак: подпись ответа
     * сверяется с ключом авторизованного responder'а, nonce обязан совпасть
     * с тем, что мы отправили в запросе.
     */
    @Throws(IOException::class, OCSPException::class, NoSuchProviderException::class, GeneralSecurityException::class)
    private fun processOcspResponse(response: ByteArray, sentNonce: ByteArray, issuer: CertificateWrapper): OcspStatus {
        val resp = OCSPResp(response)

        if (resp.status != 0) {
            return unknownStatus(message = "OCSP response status: ${resp.status}")
        }

        val brep = resp.responseObject as BasicOCSPResp

        // 1) Подпись OCSP-ответа должна быть проверена ключом авторизованного
        // responder'а — либо самого CA (issuer), либо делегированного с EKU
        // id-kp-OCSPSigning, подписанного этим CA. Без этого MITM может вернуть
        // любой статус, и мы бы его приняли как родной.
        findVerifiedResponderCertificate(brep, issuer)
            ?: return unknownStatus(message = "OCSP response signature could not be verified against any authorized responder")

        // 2) Nonce обязан вернуться и совпасть с отправленным. Если responder
        // его пропустил — это replay-vector: мы могли получить старый ответ.
        val respNonceExt = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.id)
            ?: return unknownStatus(message = "OCSP response is missing nonce (replay protection failed)")

        val responseNonce = ASN1InputStream(respNonceExt).use { asn1In ->
            val outerOctets = DEROctetString.getInstance(asn1In.readObject()).octets
            ASN1InputStream(outerOctets).use { asn2In ->
                DEROctetString.getInstance(asn2In.readObject()).octets
            }
        }
        if (!sentNonce.contentEquals(responseNonce)) {
            return unknownStatus(message = "OCSP response nonce does not match request")
        }

        // 3) Freshness: thisUpdate в будущем — аномалия, отклоняем. После
        // nextUpdate — WARN, но используем (аналогично подходу к CRL — отзывы
        // не отменяются, false negative хуже false positive).
        val singleResps = brep.responses
        if (singleResps == null || singleResps.isEmpty()) {
            return unknownStatus(message = "OCSP response has no single responses")
        }
        val singleResp = singleResps[0]

        val now = Date()

        if (singleResp.thisUpdate != null && singleResp.thisUpdate.time > now.time + CLOCK_SKEW_MS) {
            return unknownStatus(message = "OCSP response thisUpdate is in the future")
        }
        if (singleResp.nextUpdate != null && singleResp.nextUpdate.time + CLOCK_SKEW_MS < now.time) {
            log.debug("OCSP response is past its nextUpdate={}, still using", singleResp.nextUpdate)
        }

        return when (val status = singleResp.certStatus) {
            null -> OcspStatus(result = OcspResult.ACTIVE, message = "OK")
            is RevokedStatus -> {
                val reason = try {
                    status.revocationReason
                } catch (e: IllegalStateException) {
                    -1
                }
                OcspStatus(
                    result = OcspResult.REVOKED,
                    revocationTime = status.revocationTime,
                    revocationReason = reason,
                    message = "OK",
                )
            }
            else -> unknownStatus(message = "Unknown status")
        }
    }

    /**
     * Ищет сертификат, чьим ключом подпись на OCSP-ответе сходится, и при этом
     * этот сертификат имеет право быть OCSP-responder'ом для данного CA:
     *  - либо это сам issuer (CA ставит подпись своим же ключом — допустимо);
     *  - либо это делегированный responder, выпущенный этим issuer'ом и
     *    несущий EKU id-kp-OCSPSigning (RFC 6960 §4.2.2.2).
     *
     * Возвращает `null`, если ни одна комбинация не сошлась.
     */
    @Throws(NoSuchProviderException::class, OCSPException::class)
    private fun findVerifiedResponderCertificate(brep: BasicOCSPResp, issuer: CertificateWrapper): X509Certificate? {
        val issuerCert = issuer.x509Certificate
        val provider = kalkanProvider.name

        // Пробуем сначала ключ самого CA — самый частый случай для NCA.
        try {
            if (brep.verify(issuerCert.publicKey, provider)) {
                return issuerCert
            }
        } catch (e: OCSPException) {
            log.debug("OCSP response not signed by CA itself: {}", e.message)
        }

        // Делегированный responder: cert лежит внутри ответа. Проверяем
        // подпись, цепочку до issuer'а и EKU.
        val embedded = brep.getCerts(provider) ?: return null

        for (respCert in embedded) {
            try {
                if (!brep.verify(respCert.publicKey, provider)) continue
            } catch (e: OCSPException) {
                continue
            }

            // Цепочка: responder-cert подписан тем же CA.
            if (respCert.issuerX500Principal != issuerCert.subjectX500Principal) {
                log.debug("Embedded OCSP cert is not issued by our CA")
                continue
            }
            try {
                respCert.verify(issuerCert.publicKey)
            } catch (e: GeneralSecurityException) {
                log.debug("Embedded OCSP cert signature does not verify against CA: {}", e.message)
                continue
            }

            // EKU обязан содержать id-kp-OCSPSigning.
            try {
                val eku = respCert.extendedKeyUsage
                if (eku == null || EKU_OCSP_SIGNING_OID !in eku) {
                    log.debug("Embedded OCSP cert does not declare id-kp-OCSPSigning EKU")
                    continue
                }
            } catch (e: java.security.cert.CertificateParsingException) {
                continue
            }

            return respCert
        }
        return null
    }

    @Throws(IOException::class, InterruptedException::class)
    private fun makeRequest(url: String, data: ByteArray): ByteArray {
        val httpRequest = HttpRequest.newBuilder(URI(url))
            .timeout(httpClientConfiguration.requestTimeoutDuration)
            .header("User-Agent", httpClientConfiguration.effectiveUserAgent)
            .header("Content-Type", "application/ocsp-request")
            .POST(HttpRequest.BodyPublishers.ofByteArray(data))
            .build()
        return client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray()).body()
    }

    private fun unknownStatus(url: String? = null, message: String?): OcspStatus =
        OcspStatus(result = OcspResult.UNKNOWN, url = url, message = message)

    companion object {
        private val log = LoggerFactory.getLogger(OcspService::class.java)

        /** RFC 8954 рекомендует nonce длиной не менее 16 байт. */
        private const val NONCE_LENGTH = 16

        /**
         * RFC 6960 §4.2.2.2: для делегированного OCSP-responder'а EKU должен
         * содержать id-kp-OCSPSigning.
         */
        private const val EKU_OCSP_SIGNING_OID = "1.3.6.1.5.5.7.3.9"

        /** 5 минут на расхождение часов. */
        private const val CLOCK_SKEW_MS = 5L * 60 * 1000
    }
}
