package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

class PdfVerifyRequest : VerifyRequest() {
    @NotEmpty
    var pdf: String = ""
}
