package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.SbaVerifyRequest
import kz.ncanode.dto.request.X509InfoRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.service.CertificateService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "X509", description = "Методы для работы с x509")
@RestController
@RequestMapping("x509")
class X509Controller(private val certificateService: CertificateService) {

    @PostMapping("/info")
    fun info(@Valid @RequestBody request: X509InfoRequest): ResponseEntity<VerificationResponse> =
        ResponseEntity.ok(
            certificateService.info(
                request.certs,
                CertificateRevocation.OCSP in request.revocationCheck,
                CertificateRevocation.CRL in request.revocationCheck,
            )
        )

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: SbaVerifyRequest): ResponseEntity<VerificationResponse> =
        ResponseEntity.ok(
            certificateService.verify(
                request.certificate,
                request.signature,
                request.data,
                CertificateRevocation.OCSP in request.revocationCheck,
                CertificateRevocation.CRL in request.revocationCheck,
            )
        )
}
