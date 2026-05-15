package kz.ncanode.dto.response

import kz.ncanode.dto.certificate.CertificateInfo
import org.springframework.http.HttpStatus

class VerificationResponse(
    var valid: Boolean = false,
    var signers: List<CertificateInfo?> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
