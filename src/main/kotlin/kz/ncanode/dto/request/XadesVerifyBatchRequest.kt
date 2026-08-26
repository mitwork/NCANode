package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-проверка XAdES: массив XML с общими revocation-флагами
 * (наследуются через [VerifyRequest]).
 */
class XadesVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    var xmls: List<String> = emptyList()
}
