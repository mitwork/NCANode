package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант извлечения payload'а из подписанных CMS-блобов.
 * Извлечение работает только для attached CMS (signedContent внутри);
 * для detached элемент вернёт ClientException — это видно на per-item status'е.
 */
class CmsExtractBatchRequest {
    @NotEmpty
    var cms: List<String> = emptyList()
}
