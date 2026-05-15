package kz.ncanode.configuration

import kz.ncanode.service.CrlWarmupService
import org.springframework.boot.health.contributor.Health
import org.springframework.boot.health.contributor.HealthIndicator
import org.springframework.stereotype.Component

/**
 * Actuator HealthIndicator, отражающий состояние CRL warmup'а.
 *
 * Логика:
 *  - Warmup отключён (`NCANODE_CRL_WARMUP_ENABLED=false`) — статус UP всегда.
 *  - Warmup включён и завершён — UP.
 *  - Warmup включён и в процессе — DOWN (общий `/actuator/health` тоже
 *    становится DOWN).
 *
 * Зачем: при rolling-deploy load balancer health-check читает
 * `/actuator/health`. Пока инстанс не прогрел CRL-кэш, на нём первые
 * запросы будут медленные (10+ секунд для крупных GOST CRL'ей). DOWN-статус
 * удерживает LB от отправки трафика до готовности.
 */
@Component("crlWarmup")
class CrlWarmupHealthIndicator(
    private val warmupService: CrlWarmupService,
) : HealthIndicator {

    override fun health(): Health = when {
        !warmupService.isWarmupEnabled -> Health.up().withDetail("warmup", "disabled").build()
        warmupService.isWarmupComplete -> Health.up().withDetail("warmup", "complete").build()
        else -> Health.down().withDetail("warmup", "in_progress").build()
    }
}
