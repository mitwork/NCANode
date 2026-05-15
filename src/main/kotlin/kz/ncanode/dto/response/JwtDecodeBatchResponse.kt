package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-декодирования JWT. Per-item — готовый [JwtDecodeResponse]
 * со своим valid + jwt + status. Top-level — HTTP-уровень.
 */
class JwtDecodeBatchResponse(
    var results: List<JwtDecodeResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
