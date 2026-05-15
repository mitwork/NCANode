package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.CmsCreateBatchRequest
import kz.ncanode.dto.request.CmsCreateRequest
import kz.ncanode.dto.request.CmsExtractBatchRequest
import kz.ncanode.dto.request.CmsVerifyBatchRequest
import kz.ncanode.dto.request.CmsVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.response.CmsBatchResponse
import kz.ncanode.dto.response.CmsDataResponse
import kz.ncanode.dto.response.CmsExtractBatchResponse
import kz.ncanode.dto.response.CmsResponse
import kz.ncanode.dto.response.CmsVerificationBatchResponse
import kz.ncanode.dto.response.CmsVerificationResponse
import kz.ncanode.service.CmsService

/**
 * Прямые unit-вызовы методов CmsController — без Spring/MockMvc.
 * Контроллер — тонкий passthrough, цель тестов: проверить, что request
 * корректно делегируется в сервис и status=200 проставляется на body.
 *
 * HTTP/JSON binding и валидация @Valid — framework-уровень, проверяются
 * в integration-тестах сервисов (CmsServiceIntegrationTest и т.д.).
 */
class CmsControllerTest : FunSpec({

    test("POST /cms/sign delegates request to CmsService.create and returns 200") {
        val service = mockk<CmsService>()
        val expected = CmsResponse(cms = "BASE64-CMS")
        every { service.create(any()) } returns expected

        val request = CmsCreateRequest().apply { data = "AA==" }
        val response = CmsController(service).sign(request)

        response.statusCode.value() shouldBe 200
        response.body!!.cms shouldBe "BASE64-CMS"
        verify(exactly = 1) { service.create(request) }
    }

    test("POST /cms/sign/add delegates to CmsService.addSigners") {
        val service = mockk<CmsService>()
        every { service.addSigners(any()) } returns CmsResponse(cms = "CMS-WITH-EXTRA-SIGNER")

        val request = CmsCreateRequest().apply { cms = "ORIGINAL" }
        val response = CmsController(service).signAdd(request)

        response.body!!.cms shouldBe "CMS-WITH-EXTRA-SIGNER"
        verify(exactly = 1) { service.addSigners(request) }
    }

    test("POST /cms/verify forwards revocationCheck flags as OCSP/CRL booleans") {
        // Контроллер декодирует Set<CertificateRevocation> → пара boolean'ов
        // (checkOcsp, checkCrl) для сервиса. Проверяем точное соответствие.
        val service = mockk<CmsService>()
        every { service.verify(any(), any(), any(), any()) } returns CmsVerificationResponse(valid = true)

        val request = CmsVerifyRequest().apply {
            cms = "BASE64"
            data = null
            revocationCheck = setOf(CertificateRevocation.OCSP)
        }
        CmsController(service).verify(request)

        verify(exactly = 1) { service.verify("BASE64", null, /* OCSP */ true, /* CRL */ false) }
    }

    test("POST /cms/verify with empty revocationCheck disables both OCSP and CRL") {
        val service = mockk<CmsService>()
        every { service.verify(any(), any(), any(), any()) } returns CmsVerificationResponse(valid = true)

        val request = CmsVerifyRequest().apply { cms = "BASE64" }
        CmsController(service).verify(request)

        verify(exactly = 1) { service.verify("BASE64", null, false, false) }
    }

    test("POST /cms/sign/batch delegates to CmsService.createBatch") {
        val service = mockk<CmsService>()
        val batchResp = CmsBatchResponse(
            results = listOf(
                CmsBatchResponse.Item(cms = "CMS-1"),
                CmsBatchResponse.Item(cms = "CMS-2"),
            )
        )
        every { service.createBatch(any()) } returns batchResp

        val request = CmsCreateBatchRequest().apply {
            data = listOf("AA==", "BB==")
            signers = listOf(SignerRequest().apply { key = "K"; password = "P" })
        }
        val response = CmsController(service).signBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.createBatch(request) }
    }

    test("POST /cms/verify/batch delegates to CmsService.verifyBatch") {
        val service = mockk<CmsService>()
        val batchResp = CmsVerificationBatchResponse(
            results = listOf(
                CmsVerificationResponse(valid = true),
                CmsVerificationResponse(valid = false),
            )
        )
        every { service.verifyBatch(any()) } returns batchResp

        val request = CmsVerifyBatchRequest().apply {
            items = listOf(
                CmsVerifyBatchRequest.Item().apply { cms = "CMS-1" },
                CmsVerifyBatchRequest.Item().apply { cms = "CMS-2"; data = "DATA-2" },
            )
            revocationCheck = setOf(CertificateRevocation.OCSP)
        }
        val response = CmsController(service).verifyBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.verifyBatch(request) }
    }

    test("POST /cms/extract/batch delegates to CmsService.extractBatch") {
        val service = mockk<CmsService>()
        val batchResp = CmsExtractBatchResponse(
            results = listOf(
                CmsExtractBatchResponse.Item(data = "DATA-1"),
                CmsExtractBatchResponse.Item(data = "DATA-2"),
            )
        )
        every { service.extractBatch(any()) } returns batchResp

        val request = CmsExtractBatchRequest().apply {
            cms = listOf("CMS-1", "CMS-2")
        }
        val response = CmsController(service).extractBatch(request)

        response.statusCode.value() shouldBe 200
        response.body!!.results.size shouldBe 2
        verify(exactly = 1) { service.extractBatch(request) }
    }

    test("POST /cms/extract delegates to CmsService.extract") {
        val service = mockk<CmsService>()
        every { service.extract(any()) } returns CmsDataResponse(data = "ORIGINAL-PAYLOAD")

        val request = CmsVerifyRequest().apply { cms = "BASE64" }
        val response = CmsController(service).extract(request)

        response.body!!.data shouldBe "ORIGINAL-PAYLOAD"
        verify(exactly = 1) { service.extract("BASE64") }
    }
})
