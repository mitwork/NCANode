package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.Min
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Запрос на подпись PAdES (ETSI EN 319 142-1).
 */
class PadesSignRequest {
    @NotEmpty
    var pdf: String = ""

    @NotEmpty
    @Valid
    var signers: List<PadesSigner> = emptyList()

    /** Требуемый уровень подписи. По умолчанию базовый. */
    var level: AdesLevel = AdesLevel.B

    /** Политика TSA; применяется начиная с уровня T. */
    var tsaPolicy: TsaPolicy? = null

    class PadesSigner {
        @NotNull
        @Valid
        var signer: SignerRequest? = null

        var reason: String? = null
        var location: String? = null
        var contactInfo: String? = null

        /** Имя в свойствах подписи; по умолчанию — subject сертификата. */
        var name: String? = null

        /** Видимая подпись на странице документа; по умолчанию подпись невидимая. */
        @Valid
        var visibleSignature: VisibleSignature? = null
    }

    /**
     * Видимое представление подписи.
     *
     * [template] — PDF в base64, задающий внешний вид (в нём и логотип, и
     * текст, и положение на странице). Такой же контракт у NCALayer: рисование
     * оставлено вызывающему, сервис лишь размещает готовое представление.
     */
    class VisibleSignature {
        @NotEmpty
        var template: String = ""

        /** Страница документа, нумерация с единицы. */
        @Min(1)
        var page: Int = 1
    }
}
