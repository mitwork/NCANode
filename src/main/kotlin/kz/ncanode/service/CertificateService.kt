package kz.ncanode.service

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.configuration.OcspConfiguration
import kz.ncanode.constants.MessageConstants
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.Pkcs12InfoRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.exception.ServerException
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.stereotype.Service
import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.Signature
import java.security.SignatureException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

@Service
class CertificateService(
    private val crlService: CrlService,
    private val ocspService: OcspService,
    private val caService: CaService,
    private val kalkanWrapper: KalkanWrapper,
    private val ocspConfiguration: OcspConfiguration,
) {

    /**
     * Заполняет cert данными валидации (issuer, OCSP, CRL).
     *
     * Идемпотентна для OCSP и CRL: если соответствующее поле уже выставлено
     * (например, через [prefetchValidationData]), повторно не вычисляет.
     * Это позволяет вызывать prefetch один раз параллельно для всех signer'ов,
     * а потом основной цикл просто проходит через assemble без перерасчёта.
     */
    fun attachValidationData(cert: CertificateWrapper, checkOcsp: Boolean, checkCrl: Boolean) {
        cert.issuerCertificate = caService.getRootCertificateFor(cert)
        if (checkOcsp && cert.ocspStatus == null) {
            cert.ocspStatus = ocspService.verify(cert, cert.issuerCertificate)
        }
        if (checkCrl && cert.crlStatus == null) {
            cert.crlStatus = crlService.verify(cert)
        }
    }

    /**
     * Пакетный prefetch валидационных данных для списка сертификатов.
     *
     * OCSP-запросы для разных cert'ов могут идти параллельно (когда
     * `NCANODE_OCSP_PARALLEL=true` и cert'ов больше одного) — каждый
     * OCSP-запрос блокирующий, для CMS с N подписантами получаем N-кратное
     * ускорение vs последовательного [attachValidationData].
     *
     * CRL делается последовательно: даже без распараллеливания CRL-проверка
     * быстрая благодаря in-memory кэшу parsed+verified CRL'ей.
     *
     * Issuer-lookup тоже последовательный — он работает с in-memory CA-listом,
     * измеряется микросекундами.
     */
    fun prefetchValidationData(certs: List<CertificateWrapper>, checkOcsp: Boolean, checkCrl: Boolean) {
        if (certs.isEmpty() || (!checkOcsp && !checkCrl)) return

        for (cert in certs) {
            cert.issuerCertificate = caService.getRootCertificateFor(cert)
        }

        if (checkOcsp) {
            val parallel = ocspConfiguration.isParallelEnabled && certs.size > 1
            if (parallel) {
                certs.parallelStream().forEach { cert ->
                    cert.ocspStatus = ocspService.verify(cert, cert.issuerCertificate)
                }
            } else {
                for (cert in certs) {
                    cert.ocspStatus = ocspService.verify(cert, cert.issuerCertificate)
                }
            }
        }

        if (checkCrl) {
            for (cert in certs) {
                cert.crlStatus = crlService.verify(cert)
            }
        }
    }

    fun getCurrentDate(): Date = Date()

    fun verifyCerts(request: Pkcs12InfoRequest): VerificationResponse {
        var valid = true
        val date = getCurrentDate()
        val withOcsp = CertificateRevocation.OCSP in request.revocationCheck
        val withCrl = CertificateRevocation.CRL in request.revocationCheck

        val keys = kalkanWrapper.read(request.keys)
        val certs = mutableListOf<CertificateInfo>()

        for (key in keys) {
            val cert = key.certificate

            attachValidationData(cert, withOcsp, withCrl)

            if (!cert.isValid(date, withOcsp, withCrl)) {
                valid = false
            }

            certs.add(cert.toCertificateInfo(date, withOcsp, withCrl))
        }

        return VerificationResponse.builder()
            .valid(valid)
            .signers(certs)
            .build()
    }

    fun info(certsBase64: List<String>, checkOcsp: Boolean, checkCrl: Boolean): VerificationResponse {
        try {
            var valid = true
            val currentDate = getCurrentDate()
            val certs = mutableListOf<CertificateInfo?>()

            var message = "OK"
            var i = 0

            for (certBase64 in certsBase64) {
                val x509 = load(Base64.getDecoder().decode(certBase64.replace("\\s".toRegex(), "")))

                if (x509 == null) {
                    message = String.format(MessageConstants.CERT_INVALID, i)
                    certs.add(null)
                    ++i
                    valid = false
                    continue
                }

                val cert = CertificateWrapper(x509)

                attachValidationData(cert, checkOcsp, checkCrl)

                if (!cert.isValid(currentDate, checkOcsp, checkCrl)) {
                    valid = false
                }

                certs.add(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl))
                ++i
            }

            if (certsBase64.isEmpty()) {
                valid = false
            }

            return VerificationResponse.builder()
                .valid(valid)
                .signers(certs)
                .message(message)
                .build()
        } catch (e: CertificateException) {
            throw ServerException(e.message, e)
        } catch (e: NoSuchProviderException) {
            throw ServerException(e.message, e)
        } catch (e: IOException) {
            throw ServerException(e.message, e)
        }
    }

    fun verify(
        certBase64: String,
        signature: String,
        data: String,
        checkOcsp: Boolean,
        checkCrl: Boolean,
    ): VerificationResponse {
        try {
            var valid = true
            val currentDate = getCurrentDate()
            val certs = mutableListOf<CertificateInfo?>()
            var message = "OK"

            val x509 = load(Base64.getDecoder().decode(certBase64.replace("\\s".toRegex(), "")))

            if (x509 == null) {
                message = String.format(MessageConstants.CERT_INVALID, 0)
                certs.add(null)
                valid = false
                return VerificationResponse.builder()
                    .valid(valid)
                    .signers(certs)
                    .message(message)
                    .build()
            }

            val dataBytes = data.toByteArray(StandardCharsets.UTF_8)
            val signatureBytes = Base64.getDecoder().decode(signature)

            val sig = Signature.getInstance(x509.sigAlgName)
            sig.initVerify(x509.publicKey)
            sig.update(dataBytes)
            valid = sig.verify(signatureBytes)

            val cert = CertificateWrapper(x509)

            attachValidationData(cert, checkOcsp, checkCrl)

            if (!cert.isValid(currentDate, checkOcsp, checkCrl)) {
                valid = false
            }

            certs.add(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl))

            return VerificationResponse.builder()
                .valid(valid)
                .signers(certs)
                .message(message)
                .build()
        } catch (e: CertificateException) {
            throw ServerException(e.message, e)
        } catch (e: NoSuchProviderException) {
            throw ServerException(e.message, e)
        } catch (e: IOException) {
            throw ServerException(e.message, e)
        } catch (e: SignatureException) {
            throw ServerException(e.message, e)
        } catch (e: NoSuchAlgorithmException) {
            throw ServerException(e.message, e)
        } catch (e: InvalidKeyException) {
            throw ServerException(e.message, e)
        }
    }

    companion object {
        // @JvmStatic — единственный Java-caller (JwtService) использует синтаксис
        // `CertificateService.load(...)` как static. Уйдёт когда JwtService будет
        // портирован в Kotlin.
        @JvmStatic
        @Throws(CertificateException::class, NoSuchProviderException::class, IOException::class)
        fun load(cert: ByteArray): X509Certificate? =
            ByteArrayInputStream(cert).use { stream ->
                CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                    .generateCertificate(stream) as? X509Certificate
            }
    }
}
