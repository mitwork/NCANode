package kz.ncanode.service;

import kz.ncanode.wrapper.CertificateWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Прогрев in-memory CRL-кэша при старте приложения.
 *
 * Без прогрева первый user-verify платит цену парсинга и signature-verify
 * крупных GOST CRL'ей (до 10 секунд для 22MB файла). Прогрев сразу после
 * старта снимает эту цену.
 *
 * Управление: {@code NCANODE_CRL_WARMUP_ENABLED=true} (по умолчанию false —
 * фича опциональная, добавляет latency старту приложения).
 *
 * Текущее состояние доступно через {@link #isWarmupComplete()} и
 * {@link #isWarmupEnabled()} — использует {@code CrlWarmupHealthIndicator}
 * чтобы держать {@code /actuator/health} в DOWN пока прогрев не завершён.
 *
 * Прогрев запускается асинхронно в отдельном thread после
 * {@code ApplicationReadyEvent}, не блокирует Spring Boot startup.
 * Для CA-bundle (нужен для signature-verify) делается короткое ожидание
 * с timeout'ом — CaService может ещё дозагружать сертификаты.
 */
@Slf4j
@Service
public class CrlWarmupService {

    private static final long CA_BUNDLE_WAIT_TIMEOUT_MS = 60_000L;
    private static final long CA_BUNDLE_POLL_INTERVAL_MS = 500L;

    @Value("${ncanode.crl.warmupEnabled:false}")
    private boolean warmupEnabled;

    private final CrlService crlService;
    private final CrlService caCrlService;
    private final CaService caService;

    private final AtomicBoolean warmupComplete = new AtomicBoolean(false);

    public CrlWarmupService(
        CrlService crlService,
        @Qualifier("caCrlService") CrlService caCrlService,
        CaService caService
    ) {
        this.crlService = crlService;
        this.caCrlService = caCrlService;
        this.caService = caService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warmupOnReady() {
        if (!warmupEnabled) {
            warmupComplete.set(true);
            log.debug("CRL warmup disabled, marking complete immediately");
            return;
        }
        // Async — ApplicationReadyEvent listener'ы не должны блокировать.
        // HealthIndicator всё равно отдаст DOWN пока флаг не установлен.
        Thread t = new Thread(this::doWarmup, "crl-warmup");
        t.setDaemon(true);
        t.start();
    }

    private void doWarmup() {
        log.info("CRL cache warmup starting...");
        long start = System.currentTimeMillis();
        try {
            List<CertificateWrapper> cas = waitForCaBundle();
            if (cas.isEmpty()) {
                log.warn("CA bundle empty after {}ms wait — warmup will parse CRLs but skip signature verify",
                    CA_BUNDLE_WAIT_TIMEOUT_MS);
            }
            crlService.warmCache(cas);
            caCrlService.warmCache(cas);
        } catch (Exception e) {
            log.error("CRL warmup failed", e);
        } finally {
            long ms = System.currentTimeMillis() - start;
            log.info("CRL cache warmup completed in {}ms", ms);
            warmupComplete.set(true);
        }
    }

    /**
     * CaService.updateCache при initialDelay=0 запускается асинхронно через
     * TaskScheduler. К моменту ApplicationReadyEvent CA-bundle может быть
     * ещё не полностью загружен. Ждём с polling'ом до таймаута.
     */
    private List<CertificateWrapper> waitForCaBundle() {
        long deadline = System.currentTimeMillis() + CA_BUNDLE_WAIT_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            List<CertificateWrapper> cas = caService.getRootCertificates();
            if (!cas.isEmpty()) {
                return cas;
            }
            try {
                Thread.sleep(CA_BUNDLE_POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return caService.getRootCertificates();
    }

    public boolean isWarmupEnabled() {
        return warmupEnabled;
    }

    public boolean isWarmupComplete() {
        return warmupComplete.get();
    }
}
