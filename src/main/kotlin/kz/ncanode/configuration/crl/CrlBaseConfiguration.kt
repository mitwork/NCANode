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

    override var ttl: Int? = null
    override var url: String? = null
    override var delta: CrlBaseConfiguration? = null

    override val urlList: Map<String, URL>
        get() = urlMap(url, log)

    companion object {
        private val log = LoggerFactory.getLogger(CrlBaseConfiguration::class.java)
    }
}
