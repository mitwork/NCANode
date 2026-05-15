package kz.ncanode.dto.response

import kz.ncanode.dto.pdf.PdfSignerInfo

class PdfVerificationResponse(
    var valid: Boolean = false,
    var signers: List<PdfSignerInfo> = emptyList(),
) : StatusResponse()
