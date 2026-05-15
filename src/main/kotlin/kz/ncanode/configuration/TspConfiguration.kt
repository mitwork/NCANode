package kz.ncanode.configuration

import jakarta.validation.constraints.Min
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.net.MalformedURLException
import java.net.URL

@Configuration
@ConfigurationProperties(prefix = "ncanode.tsp")
open class TspConfiguration {
    var url: String? = null

    @get:Min(1)
    var retries: Int? = null

    val parsedUrl: URL?
        get() = try {
            url?.let { URL(it) }
        } catch (e: MalformedURLException) {
            null
        }
}
