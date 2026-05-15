package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-создания CMS. На каждый входной base64-payload — один [Item]
 * с собственным status'ом. Top-level status — HTTP-уровень (200 OK всегда
 * означает "batch обработан"). Per-item статус — в `results[i].status`.
 */
class CmsBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var cms: String? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
