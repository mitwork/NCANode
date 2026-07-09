package kz.ncanode.service

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.configuration.OcspConfiguration
import kz.ncanode.constants.MessageConstants
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.request.Pkcs12AliasesBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoRequest
import kz.ncanode.dto.request.SbaVerifyBatchRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.X509InfoBatchRequest
import kz.ncanode.dto.response.Pkcs12AliasesBatchResponse
import kz.ncanode.dto.response.Pkcs12InfoBatchResponse
import kz.ncanode.dto.response.SbaVerifyBatchResponse
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.X509InfoBatchResponse
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.mapPartial
import kz.ncanode.util.warnIfRevocationDisabled
import org.springframework.http.HttpStatus
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.stereotype.Service
import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.NoSuchProviderException
import java.security.Signature
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
        val withOcsp = request.checkOcsp
        val withCrl = request.checkCrl
        warnIfRevocationDisabled(withOcsp, withCrl)

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

        return VerificationResponse(valid = valid, signers = certs)
    }

    /**
     * Batch-info для X.509: каждый cert обрабатывается независимо.
     * status элемента:
     *  - 200 OK — cert успешно распарсен (revocation/validity отражены в `signer.valid`);
     *  - 400/500 — cert не распарсился (плохой base64, не x509, ASN.1-битый).
     */
    fun infoBatch(request: X509InfoBatchRequest): X509InfoBatchResponse {
        val checkOcsp = request.checkOcsp
        val checkCrl = request.checkCrl
        val items = request.certs.mapPartial({ status, message ->
            X509InfoBatchResponse.Item(status = status, message = message)
        }) { cert ->
            val response = info(listOf(cert), checkOcsp, checkCrl)
            val signer = response.signers.firstOrNull()
            if (signer == null) {
                // info() возвращает null в позиции с message типа
                // "[0]: Invalid certificate given" — это per-cert client error.
                X509InfoBatchResponse.Item(
                    status = HttpStatus.BAD_REQUEST.value(),
                    message = response.message ?: "Invalid certificate",
                )
            } else {
                X509InfoBatchResponse.Item(signer = signer)
            }
        }
        return X509InfoBatchResponse(results = items)
    }

    /**
     * Batch-info для p12: каждый ключ читается независимо.
     * status элемента:
     *  - 200 OK — p12 прочитан, cert извлечён;
     *  - 4xx/5xx — ошибка чтения (битый p12, неверный пароль и т.п.).
     */
    fun verifyCertsBatch(request: Pkcs12InfoBatchRequest): Pkcs12InfoBatchResponse {
        val items = request.keys.mapPartial({ status, message ->
            Pkcs12InfoBatchResponse.Item(status = status, message = message)
        }) { key ->
            val singleRequest = Pkcs12InfoRequest().apply {
                keys = listOf(SignerRequest().apply {
                    this.key = key.key
                    this.password = key.password
                    this.keyAlias = key.keyAlias
                })
                revocationCheck = request.revocationCheck
            }
            Pkcs12InfoBatchResponse.Item(signer = verifyCerts(singleRequest).signers.firstOrNull())
        }
        return Pkcs12InfoBatchResponse(results = items)
    }

    /**
     * Batch-чтение alias'ов из массива p12-ключей. Каждый key читается
     * по отдельности; ошибка в одном (битый p12 / неверный пароль) не
     * валит остальных — на каждый ключ отдаётся свой status + aliases.
     */
    fun aliasesBatch(request: Pkcs12AliasesBatchRequest): Pkcs12AliasesBatchResponse {
        val items = request.keys.mapPartial({ status, message ->
            Pkcs12AliasesBatchResponse.Item(status = status, message = message)
        }) { key ->
            val keystore = try {
                kalkanWrapper.read(key.key, key.keyAlias, key.password)
            } catch (e: KeyException) {
                // KeyException — checked, не наследует ApplicationException;
                // битый p12 / неверный пароль — клиентская ошибка. Конвертируем в
                // ClientException, чтобы mapPartial отдал 400 (а не 500).
                throw ClientException(e.message, e)
            }
            Pkcs12AliasesBatchResponse.Item(aliases = keystore.aliases)
        }
        return Pkcs12AliasesBatchResponse(results = items)
    }

    fun info(certsBase64: List<String>, checkOcsp: Boolean, checkCrl: Boolean): VerificationResponse {
        warnIfRevocationDisabled(checkOcsp, checkCrl)
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

            return VerificationResponse(valid = valid, signers = certs, message = message)
        } catch (e: GeneralSecurityException) {
            throw ServerException(e.message, e)
        } catch (e: IOException) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Batch-проверка SBA: каждый элемент (cert, signature, data) обрабатывается
     * независимо общими revocation-флагами. На исключение item получает
     * `valid=false` со status/message — остальные продолжают.
     */
    fun verifyBatch(request: SbaVerifyBatchRequest): SbaVerifyBatchResponse {
        val checkOcsp = request.checkOcsp
        val checkCrl = request.checkCrl
        val items = request.items.mapPartial({ status, message ->
            VerificationResponse(valid = false, status = status, message = message)
        }) { item ->
            verify(item.certificate, item.signature, item.data, checkOcsp, checkCrl)
        }
        return SbaVerifyBatchResponse(results = items)
    }

    fun verify(
        certBase64: String,
        signature: String,
        data: String,
        checkOcsp: Boolean,
        checkCrl: Boolean,
    ): VerificationResponse {
        warnIfRevocationDisabled(checkOcsp, checkCrl)
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
                return VerificationResponse(valid = valid, signers = certs, message = message)
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

            return VerificationResponse(valid = valid, signers = certs, message = message)
        } catch (e: GeneralSecurityException) {
            // CertificateException / NoSuchProvider / Signature / NoSuchAlgorithm /
            // InvalidKey — все наследники GeneralSecurityException, обрабатываются
            // одинаково (→ 500).
            throw ServerException(e.message, e)
        } catch (e: IOException) {
            throw ServerException(e.message, e)
        }
    }

    companion object {
        @Throws(CertificateException::class, NoSuchProviderException::class, IOException::class)
        fun load(cert: ByteArray): X509Certificate? =
            ByteArrayInputStream(cert).use { stream ->
                CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                    .generateCertificate(stream) as? X509Certificate
            }
    }
}
