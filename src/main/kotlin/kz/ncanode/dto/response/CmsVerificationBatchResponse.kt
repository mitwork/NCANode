package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-верификации CMS. Каждый элемент — полноценный
 * [CmsVerificationResponse] (valid + signers + tsp + status + message).
 * Top-level status — HTTP-уровень.
 */
class CmsVerificationBatchResponse(
    var results: List<CmsVerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
