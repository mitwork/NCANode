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
    /**
     * Покрывает ли `/ByteRange` этой подписи весь документ от 0 до EOF
     * (PAdES / ISO 32000-1 §12.8.1). `false` означает, что после подписанной
     * ревизии в файл дописан incremental update — подпись криптографически
     * валидна, но не защищает текущее содержимое документа.
     */
    val coversWholeDocument: Boolean = false,
)
