package kz.ncanode.dto.ades

import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.tsp.TspInfo

/**
 * Сведения о подписанте CAdES.
 *
 * [level] — уровень, который подпись **заявляет** (по наличию элементов),
 * [verifiedLevel] — до какого уровня она реально **проверена**. Пока не
 * реализована проверка LT и LTA, у подписи уровня LTA будет
 * `level = LTA, verifiedLevel = T`: это честнее, чем выдавать `valid: true`,
 * умалчивая, что архивная метка не проверялась.
 */
data class CadesSignerInfo(
    val level: AdesLevel? = null,
    val verifiedLevel: AdesLevel? = null,
    val certificates: List<CertificateInfo> = emptyList(),
    val tsp: TspInfo? = null,
)
