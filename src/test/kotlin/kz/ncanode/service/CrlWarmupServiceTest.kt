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
})
