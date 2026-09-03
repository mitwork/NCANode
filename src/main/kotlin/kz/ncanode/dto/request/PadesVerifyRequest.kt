package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/** Запрос на проверку PAdES. */
class PadesVerifyRequest : VerifyRequest() {
    @NotEmpty
    var pdf: String = ""
}
