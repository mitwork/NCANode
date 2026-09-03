package kz.ncanode.dto.request

import jakarta.validation.constraints.NotNull
import tools.jackson.databind.JsonNode

/**
 * Проверка JWS в формате JSON Serialization — общем или flattened.
 */
class JwsVerifyRequest : VerifyRequest() {
    @NotNull
    var jws: JsonNode? = null

    /**
     * Данные для detached-подписи. Должны быть теми же, что подписывали:
     * подпись считается по конкретной последовательности байт, и другой
     * порядок полей в JSON даст другую подпись.
     */
    var payload: JsonNode? = null
}
