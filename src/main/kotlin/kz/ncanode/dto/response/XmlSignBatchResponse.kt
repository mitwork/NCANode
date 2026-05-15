package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-подписи: на каждый входной XML — один [Item] с собственным
 * status'ом. Top-level status — HTTP-уровень: 200 OK всегда означает
 * "batch обработан до конца". Per-item статус смотри в `results[i].status`.
 *
 * Дизайн осознанный — partial-response позволяет клиенту увидеть, какие
 * именно документы провалились (issue malikzh/NCANode#212).
 */
class XmlSignBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var xml: String? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
