package kz.ncanode.configuration;

import kz.ncanode.service.CrlWarmupService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Actuator HealthIndicator, отражающий состояние CRL warmup'а.
 *
 * Логика:
 *  - Warmup отключён ({@code NCANODE_CRL_WARMUP_ENABLED=false}) — статус UP всегда.
 *  - Warmup включён и завершён — UP.
 *  - Warmup включён и в процессе — DOWN (общий {@code /actuator/health}
 *    тоже становится DOWN).
 *
 * Зачем: при rolling-deploy load balancer health-check читает
 * {@code /actuator/health}. Пока инстанс не прогрел CRL-кэш, на нём
 * первые запросы будут медленные (10+ секунд для крупных GOST CRL'ей).
 * DOWN-статус удерживает LB от отправки трафика до готовности.
 */
@Component("crlWarmup")
@RequiredArgsConstructor
public class CrlWarmupHealthIndicator implements HealthIndicator {

    private final CrlWarmupService warmupService;

    @Override
    public Health health() {
        if (!warmupService.isWarmupEnabled()) {
            return Health.up().withDetail("warmup", "disabled").build();
        }
        if (warmupService.isWarmupComplete()) {
            return Health.up().withDetail("warmup", "complete").build();
        }
        return Health.down().withDetail("warmup", "in_progress").build();
    }
}
