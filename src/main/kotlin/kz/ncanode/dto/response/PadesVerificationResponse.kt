package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.PadesSignatureInfo
import org.springframework.http.HttpStatus

/**
 * Результат проверки PAdES.
 *
 * [documentTimestamps] — сколько в документе документных меток времени
 * (`/DocTimeStamp`). Они не подписи и в [signatures] не попадают, но по их
 * наличию документ заявляет уровень LTA.
 */
class PadesVerificationResponse(
    var valid: Boolean = false,
    var level: AdesLevel? = null,
    var verifiedLevel: AdesLevel? = null,
    var validationStatus: AdesValidationStatus? = null,
    var subIndication: AdesSubIndication? = null,
    var signatures: List<PadesSignatureInfo> = emptyList(),
    var documentTimestamps: Int = 0,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
