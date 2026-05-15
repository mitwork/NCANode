package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.PdfSignBatchRequest
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyBatchRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.response.PdfSignBatchResponse
import kz.ncanode.dto.response.PdfSignResponse
import kz.ncanode.dto.response.PdfVerificationResponse
import kz.ncanode.dto.response.PdfVerifyBatchResponse
import kz.ncanode.service.PdfService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "PDF", description = "Методы для работы с PDF")
@RestController
@RequestMapping("pdf")
class PdfController(private val pdfService: PdfService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: PdfSignRequest): ResponseEntity<PdfSignResponse> =
        ResponseEntity.ok(pdfService.sign(request))

    @PostMapping("/sign/batch")
    fun signBatch(@Valid @RequestBody request: PdfSignBatchRequest): ResponseEntity<PdfSignBatchResponse> =
        ResponseEntity.ok(pdfService.signBatch(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: PdfVerifyRequest): ResponseEntity<PdfVerificationResponse> =
        ResponseEntity.ok(pdfService.verify(request))

    @PostMapping("/verify/batch")
    fun verifyBatch(@Valid @RequestBody request: PdfVerifyBatchRequest): ResponseEntity<PdfVerifyBatchResponse> =
        ResponseEntity.ok(pdfService.verifyBatch(request))
}
