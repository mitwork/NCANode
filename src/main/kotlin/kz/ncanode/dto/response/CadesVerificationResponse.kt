package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.CadesSignerInfo
import org.springframework.http.HttpStatus

/**
 * Результат проверки CAdES.
 *
 * [level] и [verifiedLevel] на верхнем уровне — минимум по подписантам:
 * документ не «долгоживущий», если хотя бы одна подпись в нём таковой не
 * является. Агрегировать иначе значило бы скрывать слабое звено.
 */
class CadesVerificationResponse(
    var valid: Boolean = false,
    var level: AdesLevel? = null,
    var verifiedLevel: AdesLevel? = null,
    var validationStatus: AdesValidationStatus? = null,
    var subIndication: AdesSubIndication? = null,
    var signers: List<CadesSignerInfo> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
