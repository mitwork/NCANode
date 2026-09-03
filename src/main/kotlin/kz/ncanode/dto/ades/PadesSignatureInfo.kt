package kz.ncanode.dto.ades

import kz.ncanode.dto.pdf.PdfSignerInfo

/**
 * Сведения об одной подписи PDF в терминах PAdES.
 *
 * [level] — уровень, который подпись заявляет, [verifiedLevel] — до какого
 * она подтверждена. [signer] — обычные сведения о подписанте: сертификат,
 * время, покрытие документа.
 */
data class PadesSignatureInfo(
    val level: AdesLevel? = null,
    val verifiedLevel: AdesLevel? = null,
    val validationStatus: AdesValidationStatus? = null,
    val subIndication: AdesSubIndication? = null,
    val signer: PdfSignerInfo? = null,
)
