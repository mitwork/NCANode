package kz.ncanode.dto.response

import kz.ncanode.dto.ades.AdesLevel
import org.springframework.http.HttpStatus

/**
 * Ответ batch-подписи CAdES: на каждый входной элемент — свой [Item] со
 * своим status'ом. Top-level status — HTTP-уровень: 200 означает «batch
 * обработан до конца», а не «всё получилось».
 *
 * [Item.level] повторяет одиночный ответ: фактически достигнутый уровень
 * клиент не должен выводить из того, что он просил.
 */
class CadesSignBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var cms: String? = null,
        var level: AdesLevel? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
