package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

class CmsResponse(
    var cms: String? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
