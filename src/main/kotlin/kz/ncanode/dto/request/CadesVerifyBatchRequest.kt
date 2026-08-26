package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

/**
 * Batch-проверка CAdES. Элемент — пара `cms + data?`: detached-подписи нужны
 * исходные данные, поэтому не плоский массив строк (так же устроен
 * [CmsVerifyBatchRequest]).
 *
 * Revocation-флаги общие на весь batch (наследуются через [VerifyRequest]).
 */
class CadesVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    @Valid
    var items: List<Item> = emptyList()

    class Item {
        @NotEmpty
        var cms: String = ""

        /** Для detached-подписи. Игнорируется, если данные вложены в CMS. */
        var data: String? = null
    }
}
