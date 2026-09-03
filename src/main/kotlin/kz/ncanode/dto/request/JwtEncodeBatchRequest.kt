package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [JwtEncodeRequest]: подписывает массив JWT-заголовков+payload'ов
 * одним и тем же ключом. Mass-encoding use case — серверу выгоднее принять
 * один POST на N токенов, чем N последовательных.
 */
class JwtEncodeBatchRequest {
    @NotEmpty
    var jwts: List<@Valid JwtEncodeRequest.JwtRequest> = emptyList()

    @NotEmpty
    var key: String = ""

    @NotEmpty
    var password: String = ""

    var keyAlias: String? = null
}
