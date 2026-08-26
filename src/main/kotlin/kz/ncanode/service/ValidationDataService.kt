package kz.ncanode.service

import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.wrapper.CertificateWrapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.security.cert.X509CRL
import java.util.Date
import java.security.cert.X509Certificate

/**
 * Сбор данных для проверки подписи — цепочки сертификатов и сведений об
 * отзыве, которые вшиваются в подпись уровня LT.
 *
 * Один сборщик на все три формата: различается только способ укладки
 * (`SignedData` у CAdES, `UnsignedProperties` у XAdES, словарь `/DSS` у
 * PAdES), а что именно собирать — одно и то же.
 *
 * Смысл уровня LT в том, чтобы подпись проверялась без обращения к сети и
 * после истечения сертификата. Поэтому здесь нельзя «постараться и собрать
 * что получится»: если для какого-то звена цепочки данных об отзыве нет,
 * подпись уровня LT выпускать нельзя — она выглядела бы долгоживущей, не
 * будучи таковой. Такой отказ честнее.
 */
@Service
class ValidationDataService(
    private val caService: CaService,
    private val crlService: CrlService,
    private val ocspService: OcspService,
) {

    /** Материал для встраивания. */
    class ValidationData(
        val certificates: List<X509Certificate>,
        val crls: List<X509CRL>,
        val ocspResponses: List<ByteArray>,
    )

    /**
     * Собирает материал для [signerCertificate].
     *
     * @throws ClientException если сертификат в цепочке отозван — подпись
     *   уровня LT с доказательством собственной недействительности не имеет
     *   смысла
     * @throws ServerException если данных об отзыве получить не удалось
     */
    fun collect(signerCertificate: X509Certificate): ValidationData {
        val chain = buildChain(signerCertificate)
        if (chain.size < 2) {
            throw ServerException(
                "Cannot build the certificate chain for ${signerCertificate.subjectX500Principal}: " +
                    "the issuer is not in the CA bundle (NCANODE_CA_URL)",
            )
        }

        val crls = mutableListOf<X509CRL>()
        val ocspResponses = mutableListOf<ByteArray>()

        for (index in chain.indices) {
            val wrapper = chain[index]
            val certificate = wrapper.x509Certificate

            // Корень не проверяют на отзыв: доверие к нему задаётся тем, что он
            // в trust store, а не CRL'ем, который он сам же и подписывает.
            if (certificate.issuerX500Principal == certificate.subjectX500Principal) continue
            // id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1): издатель явно сказал,
            // что отзыв этого сертификата проверять не нужно.
            if (certificate.getExtensionValue(OCSP_NO_CHECK) != null) continue

            val issuer = chain.getOrNull(index + 1)
            val responses = ocspService.collectResponses(wrapper, issuer)
            if (responses.isNotEmpty()) {
                ocspResponses.addAll(responses)
                continue
            }

            val certificateCrls = crlService.collectCrls(wrapper)
            if (certificateCrls.isEmpty()) {
                throw ServerException(
                    "No revocation data for ${certificate.subjectX500Principal}; " +
                        "an LT signature must carry it, so it cannot be produced",
                )
            }
            // Отозванность видна прямо во вшиваемом CRL — дальше идти незачем.
            certificateCrls.firstOrNull { it.getRevokedCertificate(certificate) != null }?.let {
                throw ClientException("Certificate ${certificate.subjectX500Principal} is revoked")
            }
            crls.addAll(certificateCrls)
        }

        return ValidationData(
            certificates = chain.map { it.x509Certificate },
            crls = crls.distinctBy { it.encoded.contentHashCode() },
            ocspResponses = ocspResponses.distinctBy { it.contentHashCode() },
        )
    }

    /**
     * Прикрепляет к [cert] вердикты по вшитому в подпись материалу на момент
     * [at] и сообщает, получился ли авторитетный ответ.
     *
     * Ключевое: выбор источника не «вшитый против живого», а по покрытию
     * момента (RFC 6960 §2.2, RFC 5280 §5.1.2.4–5.1.2.5) — данные авторитетны
     * только на своём интервале. Для старой подписи момент лежит в прошлом, и
     * покрывает его как раз вшитый материал; для подписи без метки времени
     * момент — «сейчас», и вшитое старое его не покроет, так что естественным
     * образом сработает живая проверка.
     *
     * Прикреплённые статусы отменяют живой запрос: `attachValidationData`
     * ходит в сеть только когда поле пустое.
     */
    fun attachEmbedded(
        cert: CertificateWrapper,
        crls: List<X509CRL>,
        ocspResponses: List<ByteArray>,
        at: Date,
    ): Boolean {
        if (cert.issuerCertificate == null) {
            cert.issuerCertificate = caService.getRootCertificateFor(cert)
        }

        val ocspStatuses = ocspService.statusOf(cert, cert.issuerCertificate, ocspResponses, at)
        val ocspAnswered = ocspStatuses.any { it.result != OcspResult.UNAVAILABLE }
        if (ocspAnswered) cert.ocspStatus = ocspStatuses

        val crlStatus = crlService.statusOf(cert, crls, at)
        val crlAnswered = crlStatus.result != CrlResult.UNAVAILABLE
        if (crlAnswered) cert.crlStatus = crlStatus

        return ocspAnswered || crlAnswered
    }

    /**
     * Цепочка от подписанта к корню по CA-бандлу. Обрывается на
     * самоподписанном сертификате либо когда издателя в бандле нет.
     */
    private fun buildChain(certificate: X509Certificate): List<CertificateWrapper> {
        val chain = mutableListOf(CertificateWrapper(certificate))
        val seen = mutableSetOf(certificate.subjectX500Principal to certificate.serialNumber)

        var current = chain.first()
        while (true) {
            val issuer = caService.getRootCertificateFor(current) ?: break
            val identity = issuer.x509Certificate.subjectX500Principal to issuer.x509Certificate.serialNumber
            // Защита от петли на кросс-подписанных сертификатах.
            if (!seen.add(identity)) break

            current.issuerCertificate = issuer
            chain.add(issuer)
            current = issuer
        }
        return chain
    }

    private companion object {
        /** id-pkix-ocsp-nocheck. */
        private const val OCSP_NO_CHECK = "1.3.6.1.5.5.7.48.1.5"

        private val log = LoggerFactory.getLogger(ValidationDataService::class.java)
    }
}
