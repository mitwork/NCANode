package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

class XmlSignRequest {
    @NotEmpty
    var xml: String = ""

    @NotEmpty
    var signers: List<@Valid SignerRequest> = emptyList()

    var isClearSignatures: Boolean = false

    var isTrimXml: Boolean = false
}
