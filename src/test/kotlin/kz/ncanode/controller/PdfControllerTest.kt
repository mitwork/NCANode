package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.response.PdfSignResponse
import kz.ncanode.dto.response.PdfVerificationResponse
import kz.ncanode.service.PdfService

class PdfControllerTest : FunSpec({

    test("POST /pdf/sign delegates to PdfService.sign and returns 200") {
        val service = mockk<PdfService>()
        every { service.sign(any()) } returns PdfSignResponse(pdf = "BASE64-PDF")

        val request = PdfSignRequest().apply { pdf = "ORIGINAL" }
        val response = PdfController(service).sign(request)

        response.statusCode.value() shouldBe 200
        response.body!!.pdf shouldBe "BASE64-PDF"
        verify(exactly = 1) { service.sign(request) }
    }

    test("POST /pdf/verify delegates to PdfService.verify and returns 200") {
        val service = mockk<PdfService>()
        every { service.verify(any()) } returns PdfVerificationResponse(valid = true)

        val request = PdfVerifyRequest().apply { pdf = "SIGNED" }
        val response = PdfController(service).verify(request)

        response.body!!.valid shouldBe true
        verify(exactly = 1) { service.verify(request) }
    }
})
