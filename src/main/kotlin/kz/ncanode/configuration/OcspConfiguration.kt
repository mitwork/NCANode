package kz.ncanode.configuration

import kz.ncanode.util.urlMap
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.net.URL

@Configuration
@ConfigurationProperties(prefix = "ncanode.ocsp")
open class OcspConfiguration {
    var url: String? = null

    /**
     * Если true — при верификации CMS с несколькими подписантами OCSP-запросы
     * для каждого signer'а уходят параллельно. Это даёт N-кратное ускорение
     * относительно последовательного флоу. Выключайте, если responder
     * ограничивает количество одновременных запросов с одного клиента
     * (rate-limit / connection-limit / per-IP throttling).
     */
    var isParallelEnabled: Boolean = true

    val urlList: Map<String, URL>
        get() = urlMap(url, log)

    companion object {
        private val log = LoggerFactory.getLogger(OcspConfiguration::class.java)
    }
}
