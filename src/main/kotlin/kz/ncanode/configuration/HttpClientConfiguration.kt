package kz.ncanode.configuration

import kz.ncanode.dto.http.HttpProxyConfig
import org.apache.http.HttpHost
import org.apache.http.auth.AuthScope
import org.apache.http.auth.UsernamePasswordCredentials
import org.apache.http.impl.client.BasicCredentialsProvider
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.impl.client.LaxRedirectStrategy
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.config.ConfigurableBeanFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import java.net.URI
import java.util.concurrent.TimeUnit

@Configuration
@ConfigurationProperties(prefix = "ncanode.http-client")
open class HttpClientConfiguration {
    var proxy: HttpProxyConfig? = null
    var connectionTtl: Int? = null
    var userAgent: String = "NCANode/${HttpClientConfiguration::class.java.`package`.implementationVersion}"

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    open fun httpClient(): CloseableHttpClient {
        val customClient = HttpClients.custom()

        val proxyConfig = proxy
        if (proxyConfig?.url?.isNotBlank() == true) {
            try {
                val proxyUrl = URI(proxyConfig.url).toURL()
                customClient.setProxy(HttpHost(proxyUrl.host, proxyUrl.port, proxyUrl.protocol))

                if (proxyConfig.username?.isNotBlank() == true) {
                    val credentials = UsernamePasswordCredentials(proxyConfig.username, proxyConfig.password)
                    val credentialsProvider = BasicCredentialsProvider()
                    credentialsProvider.setCredentials(AuthScope(proxyUrl.host, proxyUrl.port), credentials)
                    customClient.setDefaultCredentialsProvider(credentialsProvider)
                }
            } catch (e: Exception) {
                log.error("Invalid proxy url: $proxyConfig", e)
            }
        }

        connectionTtl?.let { customClient.setConnectionTimeToLive(it.toLong(), TimeUnit.SECONDS) }
        customClient.setUserAgent(userAgent)
        customClient.setRedirectStrategy(LaxRedirectStrategy())
        customClient.disableCookieManagement()

        return customClient.build()
    }

    companion object {
        private val log = LoggerFactory.getLogger(HttpClientConfiguration::class.java)
    }
}
