package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.SignaturePackaging
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Запрос на подпись XAdES (ETSI EN 319 132-1).
 */
class XadesSignRequest {
    @NotEmpty
    var xml: String = ""

    @NotEmpty
    @Valid
    var signers: List<SignerRequest> = emptyList()

    /** Требуемый уровень подписи. По умолчанию базовый. */
    var level: AdesLevel = AdesLevel.B

    /** Размещение подписи. Реализовано вкладывание подписи в документ. */
    var packaging: SignaturePackaging = SignaturePackaging.ENVELOPED

    /** Политика TSA; применяется начиная с уровня T. */
    var tsaPolicy: TsaPolicy? = null
}
