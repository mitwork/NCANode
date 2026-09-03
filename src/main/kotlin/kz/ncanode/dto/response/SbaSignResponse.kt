package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Результат подписи произвольных данных: сама подпись и сертификат, которым
 * она сделана — чтобы проверяющей стороне не пришлось искать его отдельно.
 */
class SbaSignResponse(
    var certificate: String? = null,
    var signature: String? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
