package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import tools.jackson.databind.JsonNode

/**
 * Подпись JWS в формате JSON Serialization (RFC 7515 §7.2).
 *
 * Компактной формы здесь нет намеренно: она вмещает ровно одну подпись, а
 * маршрут с несколькими подписантами — основной сценарий, ради которого JWS и
 * берут.
 */
class JwsSignRequest {
    /** Готовый JWS — для добавления подписи к уже подписанному документу. */
    var jws: JsonNode? = null

    /** Подписываемые данные. Не нужны, если [jws] уже несёт payload. */
    var payload: JsonNode? = null

    /** Не включать payload в результат (detached, RFC 7515 приложение F). */
    var detached: Boolean = false

    /** Значение заголовка `typ`; по умолчанию `JWT`. */
    var typ: String? = null

    @NotEmpty
    var signers: List<@Valid JwsSignerRequest> = emptyList()
}
