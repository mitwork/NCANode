package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-извлечения данных из CMS. На каждый CMS — один [Item];
 * `data` заполнен на успехе, иначе status/message с типом ошибки.
 */
class CmsExtractBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var data: String? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
