package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-проверки SBA. Каждый элемент — полноценный
 * [VerificationResponse] (valid + signers + status + message).
 */
class SbaVerifyBatchResponse(
    var results: List<VerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
