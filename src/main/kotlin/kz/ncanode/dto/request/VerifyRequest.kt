package kz.ncanode.dto.request

import kz.ncanode.dto.certificate.CertificateRevocation

abstract class VerifyRequest {
    var revocationCheck: Set<CertificateRevocation> = emptySet()
}
