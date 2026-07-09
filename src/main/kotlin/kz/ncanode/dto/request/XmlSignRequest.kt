package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

class XmlSignRequest {
    @NotEmpty
    var xml: String = ""

    @NotEmpty
    @Valid
    var signers: List<SignerRequest> = emptyList()

    var isClearSignatures: Boolean = false

    var isTrimXml: Boolean = false
}
