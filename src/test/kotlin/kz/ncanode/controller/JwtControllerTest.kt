package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.dto.response.JwtDecodeResponse
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
})
