package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.service.XadesService
import kz.ncanode.dto.request.XadesExtendRequest
import kz.ncanode.dto.request.XadesSignBatchRequest
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyBatchRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.dto.response.XadesResponse
import kz.ncanode.dto.response.XadesSignBatchResponse
import kz.ncanode.dto.response.XadesVerificationBatchResponse
import kz.ncanode.dto.response.XadesVerificationResponse
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "XAdES", description = "Подпись и проверка XAdES (ETSI EN 319 132-1), уровни B, T, LT и LTA")
@RestController
@RequestMapping("/xades")
class XadesController(private val xadesService: XadesService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: XadesSignRequest): ResponseEntity<XadesResponse> =
        ResponseEntity.ok(xadesService.sign(request))

    /**
     * Повышает уровень готовой подписи, не добавляя подписантов и не требуя
     * ключа. Отдельно от `/sign`: операция другая по смыслу — надстройка
     * поверх существующей подписи, а не создание новой.
     */
    @PostMapping("/extend")
    fun extend(@Valid @RequestBody request: XadesExtendRequest): ResponseEntity<XadesResponse> =
        ResponseEntity.ok(xadesService.extend(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: XadesVerifyRequest): ResponseEntity<XadesVerificationResponse> =
        ResponseEntity.ok(xadesService.verify(request))

    @PostMapping("/sign/batch")
    fun signBatch(
        @Valid @RequestBody request: XadesSignBatchRequest,
    ): ResponseEntity<XadesSignBatchResponse> = ResponseEntity.ok(xadesService.signBatch(request))

    @PostMapping("/verify/batch")
    fun verifyBatch(
        @Valid @RequestBody request: XadesVerifyBatchRequest,
    ): ResponseEntity<XadesVerificationBatchResponse> = ResponseEntity.ok(xadesService.verifyBatch(request))
}
