package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.Pkcs12AliasesBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoRequest
import kz.ncanode.dto.response.Pkcs12AliasesBatchResponse
import kz.ncanode.dto.response.Pkcs12AliasesResponse
import kz.ncanode.dto.response.Pkcs12InfoBatchResponse
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.service.CertificateService
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "PKCS12", description = "Чтение p12-хранилищ: info и aliases")
@RestController
@RequestMapping("/pkcs12")
class Pkcs12Controller(
    private val certificateService: CertificateService,
    private val kalkanWrapper: KalkanWrapper,
) {

    @PostMapping("/info")
    fun info(@Valid @RequestBody request: Pkcs12InfoRequest): ResponseEntity<VerificationResponse> =
        ResponseEntity.ok(certificateService.verifyCerts(request))

    @PostMapping("/info/batch")
    fun infoBatch(@Valid @RequestBody request: Pkcs12InfoBatchRequest): ResponseEntity<Pkcs12InfoBatchResponse> =
        ResponseEntity.ok(certificateService.verifyCertsBatch(request))

    @PostMapping("/aliases")
    fun aliases(@Valid @RequestBody request: Pkcs12InfoRequest): ResponseEntity<Pkcs12AliasesResponse> =
        ResponseEntity.ok(
            Pkcs12AliasesResponse(
                aliases = kalkanWrapper.read(request.keys).map { it.aliases },
            )
        )

    @PostMapping("/aliases/batch")
    fun aliasesBatch(@Valid @RequestBody request: Pkcs12AliasesBatchRequest): ResponseEntity<Pkcs12AliasesBatchResponse> =
        ResponseEntity.ok(certificateService.aliasesBatch(request))
}
