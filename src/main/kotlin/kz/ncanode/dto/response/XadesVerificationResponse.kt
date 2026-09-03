package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.XadesSignatureInfo
import org.springframework.http.HttpStatus

/**
 * Результат проверки XAdES. Уровни на верхнем уровне — минимум по подписям:
 * документ не сильнее своего слабого звена.
 */
class XadesVerificationResponse(
    var valid: Boolean = false,
    var level: AdesLevel? = null,
    var verifiedLevel: AdesLevel? = null,
    var validationStatus: AdesValidationStatus? = null,
    var subIndication: AdesSubIndication? = null,
    var signatures: List<XadesSignatureInfo> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
