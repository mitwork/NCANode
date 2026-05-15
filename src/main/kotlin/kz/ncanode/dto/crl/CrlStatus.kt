package kz.ncanode.dto.crl

import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import java.util.Date

data class CrlStatus(
    val result: CrlResult? = null,
    val file: String? = null,
    val revocationDate: Date? = null,
    val reason: String? = null,
) {
    fun toCertificateRevocationStatus(): CertificateRevocationStatus = CertificateRevocationStatus(
        revoked = result == CrlResult.REVOKED,
        revocationTime = revocationDate,
        by = CertificateRevocation.CRL,
        reason = reason,
    )
}
