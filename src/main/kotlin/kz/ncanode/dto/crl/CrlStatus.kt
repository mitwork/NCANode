package kz.ncanode.dto.crl

import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import kz.ncanode.dto.certificate.RevocationPolicy
import java.util.Date

data class CrlStatus(
    val result: CrlResult? = null,
    val file: String? = null,
    val revocationDate: Date? = null,
    val reason: String? = null,
) {
    /**
     * Был ли сертификат в добропорядочном состоянии на момент [signingTime]
     * по данным этого CRL (CAdES-T).
     *
     * `ACTIVE` — да. `REVOKED` — да только если отзыв произошёл строго после
     * [signingTime] и по benign-причине (см. [RevocationPolicy]); отсутствие
     * даты/причины отзыва — консервативно нет.
     */
    fun isValidAt(signingTime: Date): Boolean = when (result) {
        CrlResult.ACTIVE -> true
        CrlResult.REVOKED -> RevocationPolicy.signatureSurvivesRevocation(
            revocationDate,
            RevocationPolicy.reasonFromCrlName(reason),
            signingTime,
        )
        else -> false
    }

    fun toCertificateRevocationStatus(): CertificateRevocationStatus = CertificateRevocationStatus(
        revoked = result == CrlResult.REVOKED,
        revocationTime = revocationDate,
        by = CertificateRevocation.CRL,
        reason = reason,
    )
}
