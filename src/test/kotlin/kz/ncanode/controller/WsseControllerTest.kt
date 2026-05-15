package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.WsseSignBatchRequest
import kz.ncanode.dto.request.WsseSignRequest
import kz.ncanode.dto.request.XmlVerifyBatchRequest
import kz.ncanode.dto.request.XmlVerifyRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.WsseSignBatchResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.dto.response.XmlVerifyBatchResponse
import kz.ncanode.service.WsseService

class WsseControllerTest : FunSpec({

    test("POST /wsse/sign delegates to WsseService.sign and returns 200") {
        val service = mockk<WsseService>()
        every { service.sign(any()) } returns XmlSignResponse(xml = "<signed/>")

        val request = WsseSignRequest().apply { xml = "<orig/>"; key = "K"; password = "P" }
        val response = WsseController(service).sign(request)

        response.statusCode.value() shouldBe 200
        response.body!!.xml shouldBe "<signed/>"
        verify(exactly = 1) { service.sign(request) }
    }

    test("POST /wsse/verify forwards both OCSP and CRL flags when set") {
        val service = mockk<WsseService>()
        every { service.verify(any(), any(), any()) } returns VerificationResponse(valid = true)

        val request = XmlVerifyRequest().apply {
            xml = "<signed/>"
            revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
        }
        WsseController(service).verify(request)

        verify(exactly = 1) { service.verify("<signed/>", true, true) }
    }

    test("POST /wsse/verify with only CRL passes checkOcsp=false") {
        val service = mockk<WsseService>()
        every { service.verify(any(), any(), any()) } returns VerificationResponse(valid = true)

        val request = XmlVerifyRequest().apply {
            xml = "<signed/>"
            revocationCheck = setOf(CertificateRevocation.CRL)
        }
        WsseController(service).verify(request)

        verify(exactly = 1) { service.verify("<signed/>", false, true) }
    }

    test("POST /wsse/sign/batch delegates to WsseService.signBatch") {
        val service = mockk<WsseService>()
        every { service.signBatch(any()) } returns WsseSignBatchResponse(
            results = listOf(WsseSignBatchResponse.Item(xml = "<a/>"))
        )

        val request = WsseSignBatchRequest().apply {
            xmls = listOf("<a/>"); key = "K"; password = "P"
        }
        val response = WsseController(service).signBatch(request)

        response.statusCode.value() shouldBe 200
        verify(exactly = 1) { service.signBatch(request) }
    }

    test("POST /wsse/verify/batch delegates to WsseService.verifyBatch") {
        val service = mockk<WsseService>()
        every { service.verifyBatch(any()) } returns XmlVerifyBatchResponse(
            results = listOf(VerificationResponse(valid = true))
        )

        val request = XmlVerifyBatchRequest().apply { xmls = listOf("<signed/>") }
        val response = WsseController(service).verifyBatch(request)

        response.statusCode.value() shouldBe 200
        verify(exactly = 1) { service.verifyBatch(request) }
    }
})
