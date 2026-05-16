package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.CmsCreateBatchRequest
import kz.ncanode.dto.request.CmsCreateRequest
import kz.ncanode.dto.request.CmsExtractBatchRequest
import kz.ncanode.dto.request.CmsVerifyBatchRequest
import kz.ncanode.dto.request.CmsVerifyRequest
import kz.ncanode.dto.response.CmsBatchResponse
import kz.ncanode.dto.response.CmsDataResponse
import kz.ncanode.dto.response.CmsExtractBatchResponse
import kz.ncanode.dto.response.CmsResponse
import kz.ncanode.dto.response.CmsVerificationBatchResponse
import kz.ncanode.dto.response.CmsVerificationResponse
import kz.ncanode.service.CmsService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "CMS", description = "PKCS#7/CMS подписи (attached/detached), addSigners, CAdES-T")
@RestController
@RequestMapping("/cms")
class CmsController(private val cmsService: CmsService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: CmsCreateRequest): ResponseEntity<CmsResponse> =
        ResponseEntity.ok(cmsService.create(request))

    @PostMapping("/sign/add")
    fun signAdd(@Valid @RequestBody request: CmsCreateRequest): ResponseEntity<CmsResponse> =
        ResponseEntity.ok(cmsService.addSigners(request))

    @PostMapping("/sign/batch")
    fun signBatch(@Valid @RequestBody request: CmsCreateBatchRequest): ResponseEntity<CmsBatchResponse> =
        ResponseEntity.ok(cmsService.createBatch(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: CmsVerifyRequest): ResponseEntity<CmsVerificationResponse> =
        ResponseEntity.ok(
            cmsService.verify(
                request.cms,
                request.data,
                CertificateRevocation.OCSP in request.revocationCheck,
                CertificateRevocation.CRL in request.revocationCheck,
            )
        )

    @PostMapping("/verify/batch")
    fun verifyBatch(@Valid @RequestBody request: CmsVerifyBatchRequest): ResponseEntity<CmsVerificationBatchResponse> =
        ResponseEntity.ok(cmsService.verifyBatch(request))

    @PostMapping("/extract")
    fun extract(@Valid @RequestBody request: CmsVerifyRequest): ResponseEntity<CmsDataResponse> =
        ResponseEntity.ok(cmsService.extract(request.cms))

    @PostMapping("/extract/batch")
    fun extractBatch(@Valid @RequestBody request: CmsExtractBatchRequest): ResponseEntity<CmsExtractBatchResponse> =
        ResponseEntity.ok(cmsService.extractBatch(request))
}
