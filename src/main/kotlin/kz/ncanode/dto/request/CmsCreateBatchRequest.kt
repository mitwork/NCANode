package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Batch-вариант [CmsCreateRequest] для массового создания CMS (upstream
 * issue malikzh/NCANode#212). Один и тот же набор signer'ов и TSP/detached
 * флаги применяются ко всем элементам [data].
 *
 * Re-sign (добавление подписей в существующий CMS) намеренно не вынесен
 * в batch — это редкий use case, остаётся через /cms/sign/add по одному.
 */
class CmsCreateBatchRequest {
    /**
     * Массив base64-encoded полезных нагрузок. Каждый элемент идёт
     * в отдельный CMS.
     */
    @NotEmpty
    var data: List<String> = emptyList()

    @NotEmpty
    var signers: List<@Valid SignerRequest> = emptyList()

    var isWithTsp: Boolean = false
    var tsaPolicy: TsaPolicy? = null
    var isDetached: Boolean = false
}
