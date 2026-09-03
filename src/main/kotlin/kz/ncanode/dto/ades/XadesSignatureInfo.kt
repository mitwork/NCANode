package kz.ncanode.dto.ades

import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.tsp.TspInfo

/**
 * Сведения об одной XAdES-подписи.
 *
 * [level] — уровень, который подпись заявляет, [verifiedLevel] — до какого
 * она подтверждена. Для T это различие содержательно: метка может
 * присутствовать и не проходить проверку.
 */
data class XadesSignatureInfo(
    val level: AdesLevel? = null,
    val verifiedLevel: AdesLevel? = null,
    val validationStatus: AdesValidationStatus? = null,
    val subIndication: AdesSubIndication? = null,
    val certificate: CertificateInfo? = null,
    val tsp: TspInfo? = null,
)
