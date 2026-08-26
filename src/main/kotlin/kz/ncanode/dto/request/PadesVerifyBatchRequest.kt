package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-проверка PAdES: массив PDF с общими revocation-флагами
 * (наследуются через [VerifyRequest]).
 */
class PadesVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    var pdfs: List<String> = emptyList()
}
