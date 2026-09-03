package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/** Ответ batch-подписи: на каждый элемент — свой результат и свой status. */
class SbaSignBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var signature: String? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
