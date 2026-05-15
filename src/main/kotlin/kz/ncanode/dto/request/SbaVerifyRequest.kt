package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

class SbaVerifyRequest : VerifyRequest() {
    @NotEmpty
    var certificate: String = ""

    var signature: String = ""
    var data: String = ""
}
