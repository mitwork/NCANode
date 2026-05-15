package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.request.PdfSignBatchRequest
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyBatchRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.response.PdfSignBatchResponse
import kz.ncanode.dto.response.PdfSignResponse
import kz.ncanode.dto.response.PdfVerificationResponse
import kz.ncanode.dto.response.PdfVerifyBatchResponse
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

    test("POST /pdf/sign/batch delegates to PdfService.signBatch") {
        val service = mockk<PdfService>()
        every { service.signBatch(any()) } returns PdfSignBatchResponse(
            results = listOf(PdfSignBatchResponse.Item(pdf = "P1"), PdfSignBatchResponse.Item(pdf = "P2"))
        )

        val request = PdfSignBatchRequest().apply { pdfs = listOf("P", "Q") }
        val response = PdfController(service).signBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.signBatch(request) }
    }

    test("POST /pdf/verify/batch delegates to PdfService.verifyBatch") {
        val service = mockk<PdfService>()
        every { service.verifyBatch(any()) } returns PdfVerifyBatchResponse(
            results = listOf(PdfVerificationResponse(valid = true), PdfVerificationResponse(valid = false))
        )

        val request = PdfVerifyBatchRequest().apply { pdfs = listOf("P", "Q") }
        val response = PdfController(service).verifyBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.verifyBatch(request) }
    }
})
