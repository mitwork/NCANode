package kz.ncanode.service

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Service
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Прогрев in-memory CRL-кэша при старте приложения.
 *
 * Без прогрева первый user-verify платит цену парсинга и signature-verify
 * крупных GOST CRL'ей (до 10 секунд для 22MB файла). Прогрев сразу после
 * старта снимает эту цену.
 *
 * Управление: `NCANODE_CRL_WARMUP_ENABLED=true` (по умолчанию false —
 * фича опциональная, добавляет latency старту приложения).
 *
 * Текущее состояние доступно через [isWarmupComplete] и [isWarmupEnabled] —
 * использует `CrlWarmupHealthIndicator` чтобы держать `/actuator/health`
 * в DOWN пока прогрев не завершён.
 *
 * Прогрев запускается асинхронно в отдельном thread после
 * `ApplicationReadyEvent`, не блокирует Spring Boot startup. Для CA-bundle
 * (нужен для signature-verify) делается короткое ожидание с timeout'ом —
 * CaService может ещё дозагружать сертификаты.
 */
@Service
class CrlWarmupService(
    private val crlService: CrlService,
    @param:Qualifier("caCrlService") private val caCrlService: CrlService,
    private val caService: CaService,
) {

    @field:Value("\${ncanode.crl.warmupEnabled:false}")
    var isWarmupEnabled: Boolean = false

    private val warmupComplete = AtomicBoolean(false)

    val isWarmupComplete: Boolean get() = warmupComplete.get()

    @EventListener(ApplicationReadyEvent::class)
    fun warmupOnReady() {
        if (!isWarmupEnabled) {
            warmupComplete.set(true)
            log.debug("CRL warmup disabled, marking complete immediately")
            return
        }
        // Async — ApplicationReadyEvent listener'ы не должны блокировать.
        // HealthIndicator всё равно отдаст DOWN пока флаг не установлен.
        Thread(::doWarmup, "crl-warmup").apply {
            isDaemon = true
            start()
        }
    }

    /** Прерывание потока — своё или в причине исключения. */
    private fun interrupted(e: Throwable): Boolean {
        if (Thread.currentThread().isInterrupted) return true
        var cause: Throwable? = e
        while (cause != null) {
            if (cause is InterruptedException) return true
            cause = cause.cause
        }
        return false
    }

    private fun doWarmup() {
        log.info("CRL cache warmup starting...")
        val start = System.currentTimeMillis()
        try {
            val cas = waitForCaBundle()
            if (cas.isEmpty()) {
                log.warn(
                    "CA bundle empty after {}ms wait — warmup will parse CRLs but skip signature verify",
                    CA_BUNDLE_WAIT_TIMEOUT_MS,
                )
            }
            crlService.warmCache(cas)
            caCrlService.warmCache(cas)
        } catch (e: Exception) {
            // Остановка приложения прерывает загрузку — это не сбой, и
            // стек-трейс тут только пугает.
            if (interrupted(e)) {
                log.info("CRL cache warmup interrupted by shutdown")
            } else {
                log.error("CRL warmup failed", e)
            }
        } finally {
            log.info("CRL cache warmup completed in {}ms", System.currentTimeMillis() - start)
            warmupComplete.set(true)
        }
    }

    /**
     * CaService.updateCache при initialDelay=0 запускается асинхронно через
     * TaskScheduler. К моменту ApplicationReadyEvent CA-bundle может быть
     * ещё не полностью загружен. Ждём с polling'ом до таймаута.
     */
    private fun waitForCaBundle(): List<kz.ncanode.wrapper.CertificateWrapper> {
        val deadline = System.currentTimeMillis() + CA_BUNDLE_WAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val cas = caService.rootCertificates
            if (cas.isNotEmpty()) return cas
            try {
                Thread.sleep(CA_BUNDLE_POLL_INTERVAL_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        return caService.rootCertificates
    }

    companion object {
        private val log = LoggerFactory.getLogger(CrlWarmupService::class.java)
        private const val CA_BUNDLE_WAIT_TIMEOUT_MS = 60_000L
        private const val CA_BUNDLE_POLL_INTERVAL_MS = 500L
    }
}
