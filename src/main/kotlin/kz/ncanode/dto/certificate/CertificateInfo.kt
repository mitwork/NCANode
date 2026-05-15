package kz.ncanode.dto.certificate

import com.fasterxml.jackson.annotation.JsonInclude
import java.util.Date

@JsonInclude(JsonInclude.Include.NON_NULL)
data class CertificateInfo(
    val valid: Boolean = false,
    val revocations: List<CertificateRevocationStatus>? = null,
    val notBefore: Date? = null,
    val notAfter: Date? = null,
    val keyUsage: CertificateKeyUsage? = null,
    val serialNumber: String? = null,
    val signAlg: String? = null,
    val keyUser: Set<CertificateKeyUser>? = null,
    val publicKey: String? = null,
    val signature: String? = null,
    val subject: CertificateSubject? = null,
    val issuer: CertificateSubject? = null,
)
