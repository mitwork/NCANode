package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XmlSignBatchRequest
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.request.XmlVerifyBatchRequest
import kz.ncanode.dto.request.XmlVerifyRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignBatchResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.dto.response.XmlVerifyBatchResponse
import kz.ncanode.service.XmlService

class XmlControllerTest : FunSpec({

    test("POST /xml/sign delegates to XmlService.sign and returns 200") {
        val service = mockk<XmlService>()
        every { service.sign(any()) } returns XmlSignResponse(xml = "<signed/>")

        val request = XmlSignRequest().apply { xml = "<orig/>" }
        val response = XmlController(service).sign(request)

        response.statusCode.value() shouldBe 200
        response.body!!.xml shouldBe "<signed/>"
        verify(exactly = 1) { service.sign(request) }
    }

    test("POST /xml/verify forwards OCSP and CRL flags") {
        val service = mockk<XmlService>()
        every { service.verify(any(), any(), any()) } returns VerificationResponse(valid = true)

        val request = XmlVerifyRequest().apply {
            xml = "<signed/>"
            revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
        }
        XmlController(service).verify(request)

        verify(exactly = 1) { service.verify("<signed/>", true, true) }
    }

    test("POST /xml/sign/batch delegates to XmlService.signBatch and returns 200") {
        val service = mockk<XmlService>()
        val batchResp = XmlSignBatchResponse(
            results = listOf(
                XmlSignBatchResponse.Item(xml = "<signed-1/>"),
                XmlSignBatchResponse.Item(xml = "<signed-2/>"),
            )
        )
        every { service.signBatch(any()) } returns batchResp

        val request = XmlSignBatchRequest().apply {
            xmls = listOf("<a/>", "<b/>")
            signers = listOf(SignerRequest().apply { key = "K"; password = "P" })
        }
        val response = XmlController(service).signBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.signBatch(request) }
    }

    test("POST /xml/verify/batch delegates to XmlService.verifyBatch") {
        val service = mockk<XmlService>()
        val batchResp = XmlVerifyBatchResponse(
            results = listOf(
                VerificationResponse(valid = true),
                VerificationResponse(valid = false),
            )
        )
        every { service.verifyBatch(any()) } returns batchResp

        val request = XmlVerifyBatchRequest().apply {
            xmls = listOf("<signed-1/>", "<signed-2/>")
            revocationCheck = setOf(CertificateRevocation.OCSP)
        }
        val response = XmlController(service).verifyBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.verifyBatch(request) }
    }
})
