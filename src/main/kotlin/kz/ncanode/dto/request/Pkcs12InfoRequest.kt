package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

class Pkcs12InfoRequest : VerifyRequest() {
    @NotEmpty
    var keys: List<@Valid SignerRequest> = emptyList()
}
