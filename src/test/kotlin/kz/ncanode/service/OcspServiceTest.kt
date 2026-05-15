package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.configuration.OcspConfiguration
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.wrapper.KalkanWrapper
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.impl.client.CloseableHttpClient
import java.io.IOException

/**
 * Negative- и pure-unit покрытие OcspService без HTTP-фикстур.
 *
 * Покрывает:
 *  - generateOcspNonce(): длина (RFC 8954 ≥ 16 байт), entropy.
 *  - verify() с null-issuer'ом — короткий путь UNKNOWN.
 *  - verify() при сетевой ошибке — UNKNOWN, без проброса исключения.
 *  - verify() при мусоре в HTTP-ответе — UNKNOWN, без падения.
 *
 * Положительные ветки (ACTIVE / REVOKED / UNKNOWN на nonce mismatch)
 * требуют валидного OCSP-ответа от test.pki.gov.kz и покрываются
 * через CMS integration-тесты.
 */
class OcspServiceTest : FunSpec({

    val kalkanProvider = KalkanProvider()
    val kalkanWrapper = KalkanWrapper(kalkanProvider)
    val ocspConfig = OcspConfiguration()  // пустой — fallback URL не задан

    test("generateOcspNonce returns 16-byte array (RFC 8954)") {
        val client = mockk<CloseableHttpClient>(relaxed = true)
        val service = OcspService(kalkanProvider, ocspConfig, client)
        val nonce = service.generateOcspNonce()
        nonce.size shouldBe 16
    }

    test("generateOcspNonce produces non-equal nonces on consecutive calls") {
        // Slim entropy-проверка: SecureRandom 16 байт коллизию даёт практически
        // никогда (2^-64). Тест ловит только полный регресс (zero-fill, mock).
        val client = mockk<CloseableHttpClient>(relaxed = true)
        val service = OcspService(kalkanProvider, ocspConfig, client)
        val a = service.generateOcspNonce()
        val b = service.generateOcspNonce()
        a.contentEquals(b) shouldBe false
    }

    test("verify(cert, null) returns UNKNOWN early without HTTP") {
        // issuer == null — нет CA для верификации подписи OCSP-ответа;
        // короткий путь возвращает UNKNOWN, не пытаясь сходить за ответом.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val client = mockk<CloseableHttpClient>(relaxed = true)
        val service = OcspService(kalkanProvider, ocspConfig, client)

        val statuses = service.verify(ks.certificate, null)
        statuses shouldHaveSize 1
        statuses[0].result shouldBe OcspResult.UNKNOWN
        statuses[0].message!! shouldContain "root certificate"
    }

    test("verify() returns UNKNOWN when HTTP layer throws IOException") {
        // Network outage / responder offline / DNS fail — verify не должен
        // пробрасывать исключение наружу (это сломало бы любой verify-call
        // CMS/XML/etc.). Ожидаем UNKNOWN со страховочным месседжем.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val issuer = ks.certificate  // тот же cert как stub issuer — не должно дойти до подписи
        val client = mockk<CloseableHttpClient>().apply {
            every { execute(any()) } throws IOException("network down")
        }
        val service = OcspService(kalkanProvider, ocspConfig, client)

        val statuses = service.verify(ks.certificate, issuer)
        statuses shouldHaveSize 1
        statuses[0].result shouldBe OcspResult.UNKNOWN
    }

    test("verify() returns UNKNOWN when HTTP body is malformed OCSP response") {
        // Что-то перехватило HTTP / responder вернул HTML 500 / proxy
        // подменил body. Парсер OCSPResp бросит, verify должен это поглотить.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val issuer = ks.certificate
        val response = mockk<CloseableHttpResponse>(relaxed = true).apply {
            every { entity.content } returns "not an OCSP response".byteInputStream()
        }
        val client = mockk<CloseableHttpClient>().apply {
            every { execute(any()) } returns response
        }
        val service = OcspService(kalkanProvider, ocspConfig, client)

        val statuses = service.verify(ks.certificate, issuer)
        statuses shouldHaveSize 1
        statuses[0].result shouldBe OcspResult.UNKNOWN
    }
})
