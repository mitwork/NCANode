package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

class Pkcs12InfoRequest : VerifyRequest() {
    @NotEmpty
    @Valid
    var keys: List<SignerRequest> = emptyList()
}
