package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.WsseSignRequest
import kz.ncanode.dto.request.XmlVerifyRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.service.WsseService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "WSSE", description = "Методы для работы с WSSE")
@RestController
@RequestMapping("wsse")
class WsseController(private val wsseService: WsseService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: WsseSignRequest): ResponseEntity<XmlSignResponse> =
        ResponseEntity.ok(wsseService.sign(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: XmlVerifyRequest): ResponseEntity<VerificationResponse> =
        ResponseEntity.ok(
            wsseService.verify(
                request.xml,
                CertificateRevocation.OCSP in request.revocationCheck,
                CertificateRevocation.CRL in request.revocationCheck,
            )
        )
}
