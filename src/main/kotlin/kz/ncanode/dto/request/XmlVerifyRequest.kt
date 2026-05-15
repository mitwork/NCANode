package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

class XmlVerifyRequest : VerifyRequest() {
    @NotEmpty
    var xml: String = ""
}
