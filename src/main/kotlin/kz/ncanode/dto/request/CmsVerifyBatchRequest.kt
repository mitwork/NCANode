package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

/**
 * Batch-проверка CMS. В отличие от XML здесь каждый элемент — пара
 * `cms + data?` (data нужен для detached-CMS), поэтому не плоский
 * массив строк, а массив подобъектов.
 *
 * Revocation-флаги общие на весь batch (наследуются через [VerifyRequest]).
 */
class CmsVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    @Valid
    var items: List<Item> = emptyList()

    class Item {
        @NotEmpty
        var cms: String = ""

        /** Для detached-CMS. Игнорируется, если cms содержит signedContent. */
        var data: String? = null
    }
}
