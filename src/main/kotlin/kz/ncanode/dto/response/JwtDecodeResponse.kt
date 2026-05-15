package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

class JwtDecodeResponse(
    var valid: Boolean = false,
    var jwt: Jwt? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    data class Jwt(
        val header: Map<String, String>? = null,
        val payload: Map<String, Any?>? = null,
    )
}
