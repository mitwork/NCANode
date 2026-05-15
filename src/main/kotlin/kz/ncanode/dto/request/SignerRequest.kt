package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

class SignerRequest {
    @NotEmpty
    var key: String = ""

    @NotEmpty
    var password: String = ""

    var keyAlias: String? = null

    var referenceUri: String? = null
}
