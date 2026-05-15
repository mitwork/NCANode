package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.WsseSignRequest
import kz.ncanode.dto.request.XmlVerifyRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignResponse
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
})
