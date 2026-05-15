package kz.ncanode.controller

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kz.ncanode.dto.request.JwtDecodeBatchRequest
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeBatchRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.dto.response.JwtDecodeBatchResponse
import kz.ncanode.dto.response.JwtDecodeResponse
import kz.ncanode.dto.response.JwtEncodeBatchResponse
import kz.ncanode.dto.response.JwtEncodeResponse
import kz.ncanode.service.JwtService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Tag(name = "JWT", description = "Методы для работы с JWT")
@RestController
@RequestMapping("jwt")
class JwtController(private val jwtService: JwtService) {

    @PostMapping("/encode")
    fun encode(@Valid @RequestBody request: JwtEncodeRequest): ResponseEntity<JwtEncodeResponse> =
        ResponseEntity.ok(jwtService.encode(request))

    @PostMapping("/encode/batch")
    fun encodeBatch(@Valid @RequestBody request: JwtEncodeBatchRequest): ResponseEntity<JwtEncodeBatchResponse> =
        ResponseEntity.ok(jwtService.encodeBatch(request))

    @PostMapping("/decode")
    fun decode(@Valid @RequestBody request: JwtDecodeRequest): ResponseEntity<JwtDecodeResponse> =
        ResponseEntity.ok(jwtService.decode(request))

    @PostMapping("/decode/batch")
    fun decodeBatch(@Valid @RequestBody request: JwtDecodeBatchRequest): ResponseEntity<JwtDecodeBatchResponse> =
        ResponseEntity.ok(jwtService.decodeBatch(request))
}
