package kz.ncanode.dto.response

class JwtDecodeResponse(
    var valid: Boolean = false,
    var jwt: Jwt? = null,
) : StatusResponse() {

    data class Jwt(
        val header: Map<String, String>? = null,
        val payload: Map<String, Any?>? = null,
    )
}
