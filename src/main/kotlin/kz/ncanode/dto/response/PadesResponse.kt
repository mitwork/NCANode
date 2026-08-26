package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesLevel
import org.springframework.http.HttpStatus

/** Ответ на подпись PAdES. [level] — фактически достигнутый уровень. */
class PadesResponse(
    var pdf: String? = null,
    var level: AdesLevel? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
