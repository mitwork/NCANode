package kz.ncanode.dto.response

import org.springframework.http.HttpStatus
import tools.jackson.databind.JsonNode

/** Результат подписи: JWS в формате JSON Serialization. */
class JwsSignResponse(
    var jws: JsonNode? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
