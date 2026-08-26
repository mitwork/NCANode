package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.service.XadesService
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.dto.response.XadesResponse
import kz.ncanode.dto.response.XadesVerificationResponse
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "XAdES", description = "Подпись и проверка XAdES (ETSI EN 319 132-1), уровни B и T")
@RestController
@RequestMapping("/xades")
class XadesController(private val xadesService: XadesService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: XadesSignRequest): ResponseEntity<XadesResponse> =
        ResponseEntity.ok(xadesService.sign(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: XadesVerifyRequest): ResponseEntity<XadesVerificationResponse> =
        ResponseEntity.ok(xadesService.verify(request))
}
