package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.SbaVerifyRequest
import kz.ncanode.dto.request.X509InfoRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.service.CertificateService

class X509ControllerTest : FunSpec({

    test("POST /x509/info delegates to CertificateService.info and returns 200") {
        val service = mockk<CertificateService>()
        every { service.info(any(), any(), any()) } returns VerificationResponse(valid = true)

        val request = X509InfoRequest().apply {
            certs = listOf("CERT-1", "CERT-2")
            revocationCheck = setOf(CertificateRevocation.OCSP)
        }
        val response = X509Controller(service).info(request)

        response.statusCode.value() shouldBe 200
        verify(exactly = 1) { service.info(listOf("CERT-1", "CERT-2"), /* OCSP */ true, /* CRL */ false) }
    }

    test("POST /x509/verify (SBA) delegates with cert + signature + data + revocation flags") {
        val service = mockk<CertificateService>()
        every { service.verify(any(), any(), any(), any(), any()) } returns VerificationResponse(valid = true)

        val request = SbaVerifyRequest().apply {
            certificate = "CERT"
            signature = "SIG"
            data = "DATA"
            revocationCheck = setOf(CertificateRevocation.CRL)
        }
        X509Controller(service).verify(request)

        verify(exactly = 1) { service.verify("CERT", "SIG", "DATA", /* OCSP */ false, /* CRL */ true) }
    }
})
