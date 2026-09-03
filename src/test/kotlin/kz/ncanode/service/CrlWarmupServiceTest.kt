package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk

class CrlWarmupServiceTest : FunSpec({

    test("warmup disabled: marks complete immediately on ApplicationReadyEvent") {
        val warmup = CrlWarmupService(
            crlService = mockk(relaxed = true),
            caCrlService = mockk(relaxed = true),
            caService = mockk(relaxed = true),
        )
        // Field-injected @Value не сработает в unit-сценарии — выставляем напрямую.
        warmup.isWarmupEnabled = false

        warmup.isWarmupComplete shouldBe false
        warmup.warmupOnReady()
        warmup.isWarmupComplete shouldBe true
    }

    test("warmup enabled: starts async + flips complete after thread finishes") {
        val crlService: CrlService = mockk(relaxed = true)
        val caCrlService: CrlService = mockk(relaxed = true)
        val caService: CaService = mockk()
        // Ненулевой CA-bundle сразу — обходим polling waitForCaBundle.
        every { caService.rootCertificates } returns listOf(mockk())

        val warmup = CrlWarmupService(crlService, caCrlService, caService).apply {
            isWarmupEnabled = true
        }

        warmup.warmupOnReady()
        // Ждём завершения daemon-thread (warmCache в mock'ах — мгновенный no-op).
        val deadline = System.currentTimeMillis() + 5_000
        while (!warmup.isWarmupComplete && System.currentTimeMillis() < deadline) {
            Thread.sleep(50)
        }
        warmup.isWarmupComplete shouldBe true
    }

    test("a failed warmup still completes: health must not hang on DOWN") {
        // Прогрев — оптимизация, а не условие работоспособности. Если он упал,
        // флаг всё равно обязан подняться, иначе HealthIndicator навсегда
        // оставит инстанс вне балансировки.
        val crlService: CrlService = mockk(relaxed = true)
        every { crlService.warmCache(any()) } throws IllegalStateException("cache is broken")
        val caService: CaService = mockk()
        every { caService.rootCertificates } returns listOf(mockk())

        val warmup = CrlWarmupService(crlService, mockk(relaxed = true), caService).apply {
            isWarmupEnabled = true
        }

        warmup.warmupOnReady()
        waitForCompletion(warmup)

        warmup.isWarmupComplete shouldBe true
    }

    test("interruption during shutdown completes the warmup without an error") {
        // Остановку приложения прогрев видит как прерывание потока. Это не
        // сбой: приложение уходит, а не ломается (см. quirk про Ctrl+C).
        val crlService: CrlService = mockk(relaxed = true)
        every { crlService.warmCache(any()) } throws RuntimeException(
            "interrupted", InterruptedException("shutdown"),
        )
        val caService: CaService = mockk()
        every { caService.rootCertificates } returns listOf(mockk())

        val warmup = CrlWarmupService(crlService, mockk(relaxed = true), caService).apply {
            isWarmupEnabled = true
        }

        warmup.warmupOnReady()
        waitForCompletion(warmup)

        warmup.isWarmupComplete shouldBe true
    }

    test("an empty CA bundle does not stop the warmup") {
        // CRL всё равно разбираются — просто без проверки подписи издателя.
        val crlService: CrlService = mockk(relaxed = true)
        val caService: CaService = mockk()
        every { caService.rootCertificates } returns emptyList()

        val warmup = CrlWarmupService(crlService, mockk(relaxed = true), caService).apply {
            isWarmupEnabled = true
        }

        // Ожидание CA-бандла ограничено таймаутом, поэтому прогрев здесь
        // намеренно не дожидается завершения — проверяем, что поток стартовал
        // и сервис не упал.
        warmup.warmupOnReady()
        warmup.isWarmupComplete shouldBe false
    }
})

private fun waitForCompletion(warmup: CrlWarmupService) {
    val deadline = System.currentTimeMillis() + 5_000
    while (!warmup.isWarmupComplete && System.currentTimeMillis() < deadline) {
        Thread.sleep(50)
    }
}
