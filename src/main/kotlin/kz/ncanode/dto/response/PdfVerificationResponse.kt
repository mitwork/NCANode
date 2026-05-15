package kz.ncanode.dto.response

import kz.ncanode.dto.pdf.PdfSignerInfo
import org.springframework.http.HttpStatus

class PdfVerificationResponse(
    var valid: Boolean = false,
    var signers: List<PdfSignerInfo> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
