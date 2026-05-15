package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

class PdfVerifyBatchResponse(
    var results: List<PdfVerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
