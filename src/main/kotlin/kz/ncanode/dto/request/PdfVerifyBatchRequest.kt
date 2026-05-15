package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [PdfVerifyRequest]: проверяет массив подписанных PDF
 * одинаковыми revocation-флагами.
 */
class PdfVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    var pdfs: List<String> = emptyList()
}
