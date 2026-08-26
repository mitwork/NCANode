package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/** Запрос на проверку XAdES. */
class XadesVerifyRequest : VerifyRequest() {
    @NotEmpty
    var xml: String = ""
}
