package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

class JwtEncodeResponse(
    var jwt: String? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
