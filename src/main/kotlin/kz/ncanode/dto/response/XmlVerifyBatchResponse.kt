package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-верификации XML. Каждый элемент — полноценный
 * [VerificationResponse] (со своим valid + signers + status + message).
 * Top-level status — HTTP-уровень (200 = "обработано"), per-item
 * результат — в `results[i]`.
 */
class XmlVerifyBatchResponse(
    var results: List<VerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
