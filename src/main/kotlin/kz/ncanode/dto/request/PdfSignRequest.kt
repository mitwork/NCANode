package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull
import kz.ncanode.dto.tsp.TsaPolicy

class PdfSignRequest {
    @NotEmpty
    var pdf: String = ""

    @NotEmpty
    @Valid
    var signers: List<PdfSigner> = emptyList()

    var isWithTsp: Boolean = false

    var tsaPolicy: TsaPolicy? = null

    class PdfSigner {
        var reason: String? = null
        var location: String? = null
        var contactInfo: String? = null

        // Было `@NotEmpty lateinit var signer`: @NotEmpty на объекте — невалидный
        // target (мёртв), а отсутствие поля → lateinit не инициализирован →
        // UninitializedPropertyAccessException → 500. Теперь nullable + @NotNull
        // @Valid: отсутствие/невалидный signer ловится валидацией как 400.
        @NotNull
        @Valid
        var signer: SignerRequest? = null
    }
}
