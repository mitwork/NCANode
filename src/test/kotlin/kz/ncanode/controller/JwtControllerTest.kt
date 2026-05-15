package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.request.JwtDecodeBatchRequest
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeBatchRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.dto.response.JwtDecodeBatchResponse
import kz.ncanode.dto.response.JwtDecodeResponse
import kz.ncanode.dto.response.JwtEncodeBatchResponse
import kz.ncanode.dto.response.JwtEncodeResponse
import kz.ncanode.service.JwtService

class JwtControllerTest : FunSpec({

    test("POST /jwt/encode delegates to JwtService.encode and returns 200") {
        val service = mockk<JwtService>()
        every { service.encode(any()) } returns JwtEncodeResponse(jwt = "header.payload.sig")

        val request = JwtEncodeRequest().apply { key = "KEY"; password = "PWD" }
        val response = JwtController(service).encode(request)

        response.statusCode.value() shouldBe 200
        response.body!!.jwt shouldBe "header.payload.sig"
        verify(exactly = 1) { service.encode(request) }
    }

    test("POST /jwt/decode delegates to JwtService.decode and returns 200") {
        val service = mockk<JwtService>()
        every { service.decode(any()) } returns JwtDecodeResponse(valid = true)

        val request = JwtDecodeRequest().apply { jwt = "header.payload.sig"; key = "CERT" }
        val response = JwtController(service).decode(request)

        response.body!!.valid shouldBe true
        verify(exactly = 1) { service.decode(request) }
    }

    test("POST /jwt/encode/batch delegates to JwtService.encodeBatch") {
        val service = mockk<JwtService>()
        every { service.encodeBatch(any()) } returns JwtEncodeBatchResponse(
            results = listOf(JwtEncodeBatchResponse.Item(jwt = "j1"), JwtEncodeBatchResponse.Item(jwt = "j2"))
        )

        val request = JwtEncodeBatchRequest().apply {
            jwts = listOf(JwtEncodeRequest.JwtRequest(), JwtEncodeRequest.JwtRequest())
            key = "K"; password = "P"
        }
        val response = JwtController(service).encodeBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.encodeBatch(request) }
    }

    test("POST /jwt/decode/batch delegates to JwtService.decodeBatch") {
        val service = mockk<JwtService>()
        every { service.decodeBatch(any()) } returns JwtDecodeBatchResponse(
            results = listOf(JwtDecodeResponse(valid = true), JwtDecodeResponse(valid = false))
        )

        val request = JwtDecodeBatchRequest().apply {
            jwts = listOf("j1", "j2"); key = "CERT"
        }
        val response = JwtController(service).decodeBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.decodeBatch(request) }
    }
})
