package kz.ncanode.dto.response

import kz.ncanode.dto.jws.JwsSignerInfo
import org.springframework.http.HttpStatus
import tools.jackson.databind.JsonNode

/**
 * Результат проверки JWS.
 *
 * [valid] — все подписи действительны; вердикт по каждой отдельно в
 * [signers], потому что в документе с несколькими подписантами общий флаг не
 * говорит, кто именно не прошёл.
 */
class JwsVerifyResponse(
    var valid: Boolean = false,
    var signers: List<JwsSignerInfo> = emptyList(),
    var payload: JsonNode? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
