package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.XmlSignBatchRequest
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.request.XmlVerifyBatchRequest
import kz.ncanode.dto.request.XmlVerifyRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignBatchResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.dto.response.XmlVerifyBatchResponse
import kz.ncanode.service.XmlService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "XML", description = "XMLDSIG: подпись и верификация XML-документов")
@RestController
@RequestMapping("/xml")
class XmlController(private val xmlService: XmlService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: XmlSignRequest): ResponseEntity<XmlSignResponse> =
        ResponseEntity.ok(xmlService.sign(request))

    @PostMapping("/sign/batch")
    fun signBatch(@Valid @RequestBody request: XmlSignBatchRequest): ResponseEntity<XmlSignBatchResponse> =
        ResponseEntity.ok(xmlService.signBatch(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: XmlVerifyRequest): ResponseEntity<VerificationResponse> =
        ResponseEntity.ok(
            xmlService.verify(
                request.xml,
                request.checkOcsp,
                request.checkCrl,
            )
        )

    @PostMapping("/verify/batch")
    fun verifyBatch(@Valid @RequestBody request: XmlVerifyBatchRequest): ResponseEntity<XmlVerifyBatchResponse> =
        ResponseEntity.ok(xmlService.verifyBatch(request))
}
