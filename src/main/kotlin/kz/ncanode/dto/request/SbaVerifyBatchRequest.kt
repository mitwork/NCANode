package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [SbaVerifyRequest]. Каждый элемент массива несёт собственную
 * тройку (cert, signature, data) — обычно так выглядит проверка batch'а
 * SBA-подписей, где каждый клиент подписал разные данные собственным cert'ом.
 *
 * Revocation-флаги общие на весь batch (наследуются через [VerifyRequest]).
 */
class SbaVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    @Valid
    var items: List<Item> = emptyList()

    class Item {
        @NotEmpty
        var certificate: String = ""

        var signature: String = ""
        var data: String = ""
    }
}
