package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.JwsSignRequest
import kz.ncanode.dto.request.JwsVerifyRequest
import kz.ncanode.dto.response.JwsSignResponse
import kz.ncanode.dto.response.JwsVerifyResponse
import kz.ncanode.service.JwsService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "JWS", description = "Подпись JWS (RFC 7515) в формате JSON Serialization")
@RestController
@RequestMapping("/jws")
class JwsController(private val jwsService: JwsService) {

    @PostMapping("/sign")
    fun sign(@Valid @RequestBody request: JwsSignRequest): ResponseEntity<JwsSignResponse> =
        ResponseEntity.ok(jwsService.sign(request))

    /**
     * Добавляет подпись к готовому JWS. PATCH, а не POST: это частичное
     * обновление существующего документа — тот же URL и другой глагол, как у
     * `/cms/sign` и `/cades/sign`.
     */
    @PatchMapping("/sign")
    fun addSigners(@Valid @RequestBody request: JwsSignRequest): ResponseEntity<JwsSignResponse> =
        ResponseEntity.ok(jwsService.addSigners(request))

    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: JwsVerifyRequest): ResponseEntity<JwsVerifyResponse> =
        ResponseEntity.ok(jwsService.verify(request))
}
