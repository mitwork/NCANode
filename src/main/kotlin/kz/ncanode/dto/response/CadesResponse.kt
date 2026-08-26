package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesLevel
import org.springframework.http.HttpStatus

/**
 * Ответ на подпись CAdES. [level] — фактически достигнутый уровень: клиент
 * не должен выводить его из того, что он просил.
 */
class CadesResponse(
    var cms: String? = null,
    var level: AdesLevel? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
