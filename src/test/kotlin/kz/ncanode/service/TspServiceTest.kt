package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import kz.gov.pki.kalkan.asn1.cmp.PKIFailureInfo
import kz.gov.pki.kalkan.tsp.TimeStampResponse
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.TspException
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import kz.ncanode.configuration.HttpClientConfiguration
import java.math.BigInteger
import java.net.http.HttpClient

/**
 * Pure-unit покрытие TspService — пути, не требующие живого TSA или
 * заготовленного TSP-токена.
 *
 * Положительные ветки (create/verify на реальном токене) покрыты через
 * [CmsServiceIntegrationTest].
 */
class TspServiceTest : FunSpec({

    fun buildService(): TspService = TspService(
        client = mockk<HttpClient>(relaxed = true),
        httpClientConfiguration = HttpClientConfiguration(),
        tspConfiguration = mockk(relaxed = true),
        certificateService = mockk(relaxed = true),
    )

    test("generateNonce produces a non-zero positive value") {
        // Дефолтная реализация — System.currentTimeMillis(). Любой ответ
        // должен быть положителен; нулевой/отрицательный = регресс.
        val nonce = buildService().generateNonce()
        (nonce > BigInteger.ZERO) shouldBe true
    }

    test("a TSA rejection over the request itself is a client error, with the reason") {
        // Служба ответила отказом — токена в ответе нет вовсе. Раньше это
        // давало NullPointerException «getTimeStampToken(...) must not be
        // null»: по такому сообщению невозможно понять, что произошло.
        val response = mockk<TimeStampResponse>(relaxed = true)
        every { response.timeStampToken } returns null
        every { response.status } returns 2
        every { response.failInfo } returns PKIFailureInfo(PKIFailureInfo.badAlg)
        every { response.statusString } returns "Algorithm not supported"

        val error = shouldThrow<ClientException> { buildService().tokenOf(response) }
        error.message.shouldNotBeNull() shouldContain "status 2"
        error.message.shouldNotBeNull() shouldContain "Algorithm not supported"
    }

    test("a TSA failure on its own side stays a server error") {
        // Перегрузка или внутренний сбой службы — не вина запроса, и повторить
        // его имеет смысл.
        val response = mockk<TimeStampResponse>(relaxed = true)
        every { response.timeStampToken } returns null
        every { response.status } returns 2
        every { response.failInfo } returns PKIFailureInfo(PKIFailureInfo.systemFailure)
        every { response.statusString } returns null

        shouldThrow<TspException> { buildService().tokenOf(response) }
    }
})
