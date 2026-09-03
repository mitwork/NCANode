package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull

/**
 * Batch-вариант [SbaSignRequest]: подписывает массив строк одним ключом.
 */
class SbaSignBatchRequest {
    @NotEmpty
    var data: List<String> = emptyList()

    @NotNull
    @Valid
    var signer: SignerRequest? = null
}
