package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Batch-вариант [PdfSignRequest]: подписывает массив PDF одним и тем же
 * набором signer'ов + одинаковыми TSP/политикой. Метаданные signer'а
 * (reason/location/contactInfo) общие на весь batch.
 */
class PdfSignBatchRequest {
    @NotEmpty
    var pdfs: List<String> = emptyList()

    @NotEmpty
    var signers: List<PdfSignRequest.PdfSigner> = emptyList()

    var isWithTsp: Boolean = false

    var tsaPolicy: TsaPolicy? = null
}
