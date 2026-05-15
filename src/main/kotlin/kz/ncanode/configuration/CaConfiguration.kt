package kz.ncanode.configuration

import kz.ncanode.util.urlMap
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.net.URL

@Configuration
@ConfigurationProperties(prefix = "ncanode.ca")
open class CaConfiguration {
    var isEnabled: Boolean = true
    var url: String? = null
    var ttl: Int? = null

    val urlList: Map<String, URL>
        get() = urlMap(url, log)

    companion object {
        private val log = LoggerFactory.getLogger(CaConfiguration::class.java)
    }
}
