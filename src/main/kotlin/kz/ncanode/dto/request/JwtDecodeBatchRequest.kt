package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [JwtDecodeRequest]: проверяет массив JWT одним и тем же
 * сертификатом. Mass-verify use case.
 */
class JwtDecodeBatchRequest {
    @NotEmpty
    var jwts: List<String> = emptyList()

    @NotEmpty
    var key: String = ""
}
