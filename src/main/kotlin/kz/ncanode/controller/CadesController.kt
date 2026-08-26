package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.service.CadesService
import kz.ncanode.dto.request.CadesSignRequest
import kz.ncanode.dto.request.CadesVerifyRequest
import kz.ncanode.dto.response.CadesResponse
import kz.ncanode.dto.response.CadesVerificationResponse
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "CAdES", description = "Подпись CAdES (ETSI EN 319 122-1), уровни B и T")
@RestController
@RequestMapping("/cades")
class CadesController(private val cadesService: CadesService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: CadesSignRequest): ResponseEntity<CadesResponse> =
        ResponseEntity.ok(cadesService.sign(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: CadesVerifyRequest): ResponseEntity<CadesVerificationResponse> =
        ResponseEntity.ok(cadesService.verify(request))
}
