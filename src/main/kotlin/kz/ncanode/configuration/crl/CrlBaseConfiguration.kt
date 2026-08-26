package kz.ncanode.configuration.crl

import kz.ncanode.util.urlMap
import org.slf4j.LoggerFactory
import java.net.URL

open class CrlBaseConfiguration : CrlConfiguration {
    override var isEnabled: Boolean = true

    /**
     * Если true — распарсенные и подпись-верифицированные CRL'и кэшируются
     * в памяти до изменения файла на диске. Без кэша на каждый verify-call
     * идёт повторный парсинг + signature verify, что критично для крупных
     * GOST CRL'ей (десятки секунд на запрос).
     */
    override var isCacheEnabled: Boolean = true

    /**
     * Если true — при старте все CRL'и из disk-кэша предзагружаются и
     * подпись-верифицируются в in-memory cache. Первый пользовательский
     * verify-запрос не тратит время на парсинг крупных GOST CRL'ей.
     *
     * При включённом warmup HealthIndicator `crlWarmup` держит статус
     * DOWN пока прогрев не завершён — load balancer не пошлёт на инстанс
     * трафик, пока он реально готов отвечать быстро.
     */
    override var isWarmupEnabled: Boolean = false

    /**
     * SSRF strict-режим: on-demand fetch по CRL DP серта отключён (см.
     * [CrlConfiguration.isStrict]). Оба конфига (`ncanode.crl.*` и
     * `ncanode.ca.crl.*`) мапятся на один env `NCANODE_CRL_STRICT`.
     */
    override var isStrict: Boolean = false

    /**
     * Потолок размера скачиваемого CRL (см. [CrlConfiguration.maxSizeMb]).
     * 64 МБ — примерно трёхкратный запас к боевому `nca_gost_2022.crl`
     * (~20 МБ). Оба конфига мапятся на один env `NCANODE_CRL_MAX_SIZE_MB`.
     */
    override var maxSizeMb: Int = 64

    /**
     * Размер on-demand кэша (см. [CrlConfiguration.onDemandMaxEntries]).
     * Оба конфига мапятся на один env `NCANODE_CRL_ONDEMAND_MAX`.
     */
    override var onDemandMaxEntries: Int = 64

    override var ttl: Int? = null
    override var url: String? = null
    override var delta: CrlBaseConfiguration? = null

    override val urlList: Map<String, URL>
        get() = urlMap(url, log)

    companion object {
        private val log = LoggerFactory.getLogger(CrlBaseConfiguration::class.java)
    }
}
