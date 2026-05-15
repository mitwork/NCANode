package kz.ncanode.dto.response

import kz.ncanode.dto.cms.CmsSignerInfo
import org.springframework.http.HttpStatus

class CmsVerificationResponse(
    var valid: Boolean = false,
    var signers: List<CmsSignerInfo> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
