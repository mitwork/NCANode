package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesLevel
import org.springframework.http.HttpStatus

/** Ответ batch-подписи PAdES. Top-level status — HTTP-уровень. */
class PadesSignBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var pdf: String? = null,
        var level: AdesLevel? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
