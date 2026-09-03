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
import kz.ncanode.configuration.BoundedResponse
import kz.ncanode.configuration.TspConfiguration
import java.net.http.HttpRequest
import kz.gov.pki.kalkan.tsp.TSPAlgorithms
import kz.ncanode.TestResources
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

    // Провайдер Kalkan нужен даже здесь: без него хэш не посчитать, и все
    // отказы выглядели бы одинаково — «нет такого провайдера» (quirk #16).
    TestResources.bootstrap()


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

    test("a non-200 answer from the TSA is a TSP failure, not a silent null") {
        val configuration = mockk<HttpClientConfiguration>(relaxed = true)
        every { configuration.requestBuilder(any()) } answers {
            HttpRequest.newBuilder(firstArg<java.net.URI>())
        }
        every { configuration.sendBounded(any(), any()) } returns BoundedResponse(503, ByteArray(0))

        val tspConfiguration = mockk<TspConfiguration>(relaxed = true)
        every { tspConfiguration.parsedUrl } returns java.net.URI("http://tsa.example/tsp").toURL()
        every { tspConfiguration.retries } returns 1

        val service = TspService(
            client = mockk(relaxed = true),
            httpClientConfiguration = configuration,
            tspConfiguration = tspConfiguration,
            certificateService = mockk(relaxed = true),
        )

        val error = shouldThrow<TspException> {
            service.create("данные".toByteArray(), TSPAlgorithms.SHA256, "1.2.3.4")
        }
        error.message.orEmpty() shouldContain "503"
    }

    test("an unconfigured TSA address is reported before any request") {
        val tspConfiguration = mockk<TspConfiguration>(relaxed = true)
        every { tspConfiguration.parsedUrl } returns null
        every { tspConfiguration.retries } returns 1

        val service = TspService(
            client = mockk(relaxed = true),
            httpClientConfiguration = mockk(relaxed = true),
            tspConfiguration = tspConfiguration,
            certificateService = mockk(relaxed = true),
        )

        shouldThrow<TspException> { service.create("данные".toByteArray(), TSPAlgorithms.SHA256, "1.2.3.4") }
    }

    test("an unknown hash algorithm fails before any request to the TSA") {
        // Алгоритм приходит из запроса; неизвестный — повод отказать сразу,
        // а не идти в службу за меткой, которую всё равно не посчитать.
        shouldThrow<TspException> {
            buildService().create("данные".toByteArray(), "НЕТ-ТАКОГО", "1.2.3.4")
        }
    }
})
