package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

class CmsVerifyRequest : VerifyRequest() {
    @NotEmpty
    var cms: String = ""

    var data: String? = null
}
