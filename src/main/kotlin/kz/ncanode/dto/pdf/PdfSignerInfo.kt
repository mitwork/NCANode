package kz.ncanode.dto.pdf

import kz.ncanode.dto.certificate.CertificateInfo
import java.util.Date

data class PdfSignerInfo(
    val isValid: Boolean = false,
    val reason: String? = null,
    val location: String? = null,
    val contactInfo: String? = null,
    val signDate: Date? = null,
    val certificate: CertificateInfo? = null,
    val signatureAlgorithm: String? = null,
    val digestAlgorithm: String? = null,
)
