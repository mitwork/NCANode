package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.PadesSignRequest
import kz.ncanode.dto.request.PadesVerifyRequest
import kz.ncanode.dto.response.PadesResponse
import kz.ncanode.dto.response.PadesVerificationResponse
import kz.ncanode.service.PadesService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "PAdES", description = "Подпись и проверка PAdES (ETSI EN 319 142-1), уровни B и T")
@RestController
@RequestMapping("/pades")
class PadesController(private val padesService: PadesService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: PadesSignRequest): ResponseEntity<PadesResponse> =
        ResponseEntity.ok(padesService.sign(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: PadesVerifyRequest): ResponseEntity<PadesVerificationResponse> =
        ResponseEntity.ok(padesService.verify(request))
}
