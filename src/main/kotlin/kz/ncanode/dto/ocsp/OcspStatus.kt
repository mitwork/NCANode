package kz.ncanode.dto.ocsp

import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import kz.ncanode.dto.certificate.RevocationPolicy
import kz.ncanode.dto.certificate.RevocationResult
import java.security.cert.CRLReason
import java.util.Date

data class OcspStatus(
    val result: OcspResult? = null,
    val revocationTime: Date? = null,
    val revocationReason: Int = 0,
    val message: String? = null,
    val url: String? = null,
) {
    /**
     * Был ли сертификат в добропорядочном состоянии на момент [signingTime]
     * по данным этого OCSP-ответа (CAdES-T).
     *
     * `ACTIVE` — да. `REVOKED` — да только если отзыв произошёл строго после
     * [signingTime] и по benign-причине (см. [RevocationPolicy]). `UNKNOWN`,
     * `UNAVAILABLE` и отсутствие времени отзыва — консервативно нет
     * (возможность деградации UNAVAILABLE→CRL решается уровнем выше,
     * в `CertificateWrapper.isValid`, а не здесь).
     */
    fun isValidAt(signingTime: Date): Boolean = when (result) {
        OcspResult.ACTIVE -> true
        OcspResult.REVOKED -> RevocationPolicy.signatureSurvivesRevocation(
            revocationTime,
            RevocationPolicy.reasonFromOcspCode(revocationReason),
            signingTime,
        )
        else -> false
    }

    fun toCertificateRevocationStatus(): CertificateRevocationStatus = CertificateRevocationStatus(
        revoked = result == OcspResult.REVOKED,
        revocationTime = revocationTime,
        by = CertificateRevocation.OCSP,
        reason = mapReason(),
        result = when (result) {
            OcspResult.ACTIVE -> RevocationResult.ACTIVE
            OcspResult.REVOKED -> RevocationResult.REVOKED
            OcspResult.UNAVAILABLE -> RevocationResult.UNAVAILABLE
            // null result — ответа не было по неустановленной причине,
            // консервативно UNKNOWN.
            else -> RevocationResult.UNKNOWN
        },
    )

    /**
     * Маппит int-код причины отзыва из OCSP-ответа (RFC 5280 §5.3.1)
     * в имя [CRLReason]. Ordinals enum-а совпадают с RFC-кодами 1:1
     * (UNSPECIFIED=0, KEY_COMPROMISE=1, ...AA_COMPROMISE=10), включая
     * placeholder UNUSED=7.
     *
     * Для не-REVOKED статусов используем поле [message] как раньше (обычно "OK").
     */
    private fun mapReason(): String? {
        if (result != OcspResult.REVOKED) return message
        // -1 ставится в OcspService когда IllegalStateException — поле
        // отсутствует в ответе. По RFC 5280 §5.3.1 отсутствие = unspecified.
        if (revocationReason < 0) return CRLReason.UNSPECIFIED.name
        val values = CRLReason.entries
        return if (revocationReason < values.size) values[revocationReason].name
        else CRLReason.UNSPECIFIED.name
    }
}
