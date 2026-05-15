package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull

class JwtDecodeRequest {
    @NotNull
    var jwt: String = ""

    @NotEmpty
    var key: String = ""
}
