package kz.ncanode.dto.ocsp

import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import java.security.cert.CRLReason
import java.util.Date

data class OcspStatus(
    val result: OcspResult? = null,
    val revocationTime: Date? = null,
    val revocationReason: Int = 0,
    val message: String? = null,
    val url: String? = null,
) {
    val isActive: Boolean get() = result == OcspResult.ACTIVE

    fun toCertificateRevocationStatus(): CertificateRevocationStatus = CertificateRevocationStatus(
        revoked = result == OcspResult.REVOKED,
        revocationTime = revocationTime,
        by = CertificateRevocation.OCSP,
        reason = mapReason(),
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
