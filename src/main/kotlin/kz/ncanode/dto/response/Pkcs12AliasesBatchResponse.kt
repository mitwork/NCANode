package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-чтения alias'ов из p12. На каждый ключ — один [Item]:
 *  - status 200: p12 прочитан, `aliases` — список alias'ов в ключе;
 *  - status 4xx/5xx: ошибка чтения ключа (битый p12, неверный пароль).
 */
class Pkcs12AliasesBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var aliases: List<String> = emptyList(),
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
