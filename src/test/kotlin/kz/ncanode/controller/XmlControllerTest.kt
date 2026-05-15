package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.request.XmlVerifyRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignResponse
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
})
