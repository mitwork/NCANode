package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-подписи WSSE. На каждый входной envelope — один [Item]
 * со своим status'ом. Семантика та же что у XmlSignBatchResponse:
 * partial-response, top-level HTTP-уровень.
 */
class WsseSignBatchResponse(
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
