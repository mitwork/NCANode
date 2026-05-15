package kz.ncanode.dto.response

import kz.ncanode.dto.certificate.CertificateInfo

class VerificationResponse(
    var valid: Boolean = false,
    var signers: List<CertificateInfo?> = emptyList(),
) : StatusResponse()
