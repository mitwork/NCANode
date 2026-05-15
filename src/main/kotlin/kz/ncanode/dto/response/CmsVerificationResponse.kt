package kz.ncanode.dto.response

import kz.ncanode.dto.cms.CmsSignerInfo

class CmsVerificationResponse(
    var valid: Boolean = false,
    var signers: List<CmsSignerInfo> = emptyList(),
) : StatusResponse()
