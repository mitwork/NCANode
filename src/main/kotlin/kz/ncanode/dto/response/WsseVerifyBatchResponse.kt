package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-верификации WSSE. Каждый элемент — полноценный
 * [VerificationResponse]. Отделён от [XmlVerifyBatchResponse] по
 * той же причине, что и [kz.ncanode.dto.request.WsseVerifyBatchRequest]:
 * сейчас формат идентичен, но независимость даёт пространство для
 * WSSE-специфичных дополнений без коробления XML-side.
 */
class WsseVerifyBatchResponse(
    var results: List<VerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
