package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.SignaturePackaging
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Batch-вариант [XadesSignRequest]: подписывает массив XML одним и тем же
 * набором signer'ов до одного уровня.
 */
class XadesSignBatchRequest {
    @NotEmpty
    var xmls: List<String> = emptyList()

    @NotEmpty
    var signers: List<@Valid SignerRequest> = emptyList()

    /** Требуемый уровень подписи. По умолчанию базовый. */
    var level: AdesLevel = AdesLevel.B

    /** Размещение подписи. Реализовано вкладывание подписи в документ. */
    var packaging: SignaturePackaging = SignaturePackaging.ENVELOPED

    /** Политика TSA; применяется начиная с уровня T. */
    var tsaPolicy: TsaPolicy? = null
}
