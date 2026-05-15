package kz.ncanode.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "ncanode.system")
open class SystemConfiguration {
    var isDetailedErrors: Boolean = false
    var cacheDir: String? = null
}
