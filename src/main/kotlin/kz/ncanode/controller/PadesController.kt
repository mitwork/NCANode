package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.PadesSignBatchRequest
import kz.ncanode.dto.request.PadesSignRequest
import kz.ncanode.dto.request.PadesVerifyBatchRequest
import kz.ncanode.dto.request.PadesVerifyRequest
import kz.ncanode.dto.response.PadesResponse
import kz.ncanode.dto.response.PadesSignBatchResponse
import kz.ncanode.dto.response.PadesVerificationBatchResponse
import kz.ncanode.dto.response.PadesVerificationResponse
import kz.ncanode.service.PadesService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "PAdES", description = "Подпись и проверка PAdES (ETSI EN 319 142-1), уровни B, T, LT и LTA")
@RestController
@RequestMapping("/pades")
class PadesController(private val padesService: PadesService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: PadesSignRequest): ResponseEntity<PadesResponse> =
        ResponseEntity.ok(padesService.sign(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: PadesVerifyRequest): ResponseEntity<PadesVerificationResponse> =
        ResponseEntity.ok(padesService.verify(request))

    @PostMapping("/sign/batch")
    fun signBatch(
        @Valid @RequestBody request: PadesSignBatchRequest,
    ): ResponseEntity<PadesSignBatchResponse> = ResponseEntity.ok(padesService.signBatch(request))

    @PostMapping("/verify/batch")
    fun verifyBatch(
        @Valid @RequestBody request: PadesVerifyBatchRequest,
    ): ResponseEntity<PadesVerificationBatchResponse> = ResponseEntity.ok(padesService.verifyBatch(request))
}
