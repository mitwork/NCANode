package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
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

})
