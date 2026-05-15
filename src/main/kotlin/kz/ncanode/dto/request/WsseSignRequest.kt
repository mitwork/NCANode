package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

class WsseSignRequest {
    @NotEmpty
    var xml: String = ""

    @NotEmpty
    var key: String = ""

    @NotEmpty
    var password: String = ""

    var keyAlias: String? = null

    var isTrimXml: Boolean = false
}
