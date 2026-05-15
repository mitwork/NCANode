package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.request.Pkcs12InfoBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.response.Pkcs12InfoBatchResponse
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.service.CertificateService
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.KeyStoreWrapper

class Pkcs12ControllerTest : FunSpec({

    test("POST /pkcs12/info delegates to CertificateService.verifyCerts") {
        val certService = mockk<CertificateService>()
        val kalkanWrapper = mockk<KalkanWrapper>()
        every { certService.verifyCerts(any()) } returns VerificationResponse(valid = true)

        val request = Pkcs12InfoRequest().apply {
            keys = listOf(SignerRequest().apply { key = "K"; password = "P" })
        }
        val response = Pkcs12Controller(certService, kalkanWrapper).info(request)

        response.statusCode.value() shouldBe 200
        response.body!!.valid shouldBe true
        verify(exactly = 1) { certService.verifyCerts(request) }
    }

    test("POST /pkcs12/info/batch delegates to CertificateService.verifyCertsBatch") {
        val certService = mockk<CertificateService>()
        val kalkanWrapper = mockk<KalkanWrapper>()
        every { certService.verifyCertsBatch(any()) } returns Pkcs12InfoBatchResponse(
            results = listOf(Pkcs12InfoBatchResponse.Item(), Pkcs12InfoBatchResponse.Item())
        )

        val request = Pkcs12InfoBatchRequest().apply {
            keys = listOf(
                SignerRequest().apply { key = "K1"; password = "P" },
                SignerRequest().apply { key = "K2"; password = "P" },
            )
        }
        val response = Pkcs12Controller(certService, kalkanWrapper).infoBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { certService.verifyCertsBatch(request) }
    }

    test("POST /pkcs12/aliases reads keys via KalkanWrapper and returns list of alias lists") {
        val certService = mockk<CertificateService>()
        val kalkanWrapper = mockk<KalkanWrapper>()
        val ksOne = mockk<KeyStoreWrapper> { every { aliases } returns listOf("alias-1") }
        val ksTwo = mockk<KeyStoreWrapper> { every { aliases } returns listOf("alias-2a", "alias-2b") }
        every { kalkanWrapper.read(any<List<SignerRequest>>()) } returns listOf(ksOne, ksTwo)

        val request = Pkcs12InfoRequest().apply {
            keys = listOf(
                SignerRequest().apply { key = "K1"; password = "P" },
                SignerRequest().apply { key = "K2"; password = "P" },
            )
        }
        val response = Pkcs12Controller(certService, kalkanWrapper).aliases(request)

        response.body!!.aliases shouldBe listOf(listOf("alias-1"), listOf("alias-2a", "alias-2b"))
        verify(exactly = 1) { kalkanWrapper.read(request.keys) }
    }
})
