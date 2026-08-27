package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Batch-вариант [PadesSignRequest]: подписывает массив PDF одним и тем же
 * набором signer'ов до одного уровня.
 *
 * Метаданные подписанта — включая видимое представление и номер страницы —
 * общие на весь batch: они часть подписанта, а не документа.
 */
class PadesSignBatchRequest {
    @NotEmpty
    var pdfs: List<String> = emptyList()

    @NotEmpty
    var signers: List<@Valid PadesSignRequest.PadesSigner> = emptyList()

    /** Требуемый уровень подписи. По умолчанию базовый. */
    var level: AdesLevel = AdesLevel.B

    /** Политика TSA; применяется начиная с уровня T. */
    var tsaPolicy: TsaPolicy? = null
}
