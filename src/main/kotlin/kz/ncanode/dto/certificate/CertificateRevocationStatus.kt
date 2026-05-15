package kz.ncanode.dto.certificate

import java.util.Date

data class CertificateRevocationStatus(
    val revoked: Boolean = false,
    val by: CertificateRevocation? = null,
    val revocationTime: Date? = null,
    val reason: String? = null,
)
