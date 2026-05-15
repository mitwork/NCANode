package kz.ncanode.dto.request

import jakarta.validation.constraints.NotNull

class X509InfoRequest : VerifyRequest() {
    @NotNull
    var certs: List<String> = emptyList()
}
