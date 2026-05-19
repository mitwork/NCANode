package kz.ncanode.configuration

import kz.ncanode.dto.http.HttpProxyConfig
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.config.ConfigurableBeanFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import java.net.Authenticator
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.ProxySelector
import java.net.URI
import java.net.http.HttpClient
import java.time.Duration

@Configuration
@ConfigurationProperties(prefix = "ncanode.http-client")
open class HttpClientConfiguration {
    var proxy: HttpProxyConfig? = null
    var connectTimeout: Int = 5
    var requestTimeout: Int = 30
    var userAgent: String = ""

    /**
     * Эффективный User-Agent: переопределение из конфига, если задано
     * непустым; иначе дефолтный `NCANode/<version>`.
     *
     * Пустой User-Agent отправлять нельзя — некоторые firewall/IPS
     * (наблюдалось на трафике к pki.gov.kz через Astana IX) фингерпринтят
     * `User-Agent: ` как bot/scraper и редиректят на captive portal с 303.
     */
    val effectiveUserAgent: String
        get() = userAgent.takeIf { it.isNotBlank() }
            ?: "NCANode/${HttpClientConfiguration::class.java.`package`.implementationVersion ?: "dev"}"

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    open fun httpClient(): HttpClient {
        val builder = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(connectTimeout.toLong()))
            // Detection: без явного NO_PROXY JDK HttpClient может подхватить
            // ProxySelector.getDefault() из системных свойств — поведение зависит
            // от окружения. Apache 4.x игнорировал системные настройки, для
            // совместимости форсим NO_PROXY. Свой прокси по-прежнему задаётся
            // через NCANODE_PROXY_URL (см. configureProxy).
            .proxy(HttpClient.Builder.NO_PROXY)

        configureProxy(builder)

        return builder.build()
    }

    /**
     * Per-request timeout (общий бюджет запроса). Сервисы выставляют его при
     * сборке HttpRequest через [java.net.http.HttpRequest.Builder.timeout].
     */
    val requestTimeoutDuration: Duration
        get() = Duration.ofSeconds(requestTimeout.toLong())

    private fun configureProxy(builder: HttpClient.Builder) {
        val proxyConfig = proxy ?: return
        val urlValue = proxyConfig.url
        if (urlValue.isNullOrBlank()) return

        try {
            val proxyUri = URI(urlValue)
            val host = proxyUri.host ?: throw IllegalArgumentException("missing host")
            val port = if (proxyUri.port != -1) proxyUri.port else defaultPortForScheme(proxyUri.scheme)
            builder.proxy(ProxySelector.of(InetSocketAddress(host, port)))

            val user = proxyConfig.username
            if (!user.isNullOrBlank()) {
                // Basic-auth для прокси через HTTPS-туннель отключён в JDK
                // по умолчанию (CVE-2016-5597). Разрешаем явно — наши пользователи
                // знают что подключают, и у нас единственный сценарий — внутренние
                // корпоративные прокси с basic.
                System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "")
                System.setProperty("jdk.http.auth.proxying.disabledSchemes", "")

                val password = proxyConfig.password?.toCharArray() ?: CharArray(0)
                builder.authenticator(object : Authenticator() {
                    override fun getPasswordAuthentication(): PasswordAuthentication =
                        PasswordAuthentication(user, password)
                })
            }
        } catch (e: Exception) {
            log.error("Invalid proxy url: $proxyConfig", e)
        }
    }

    private fun defaultPortForScheme(scheme: String?): Int = when (scheme?.lowercase()) {
        "https" -> 443
        else -> 80
    }

    companion object {
        private val log = LoggerFactory.getLogger(HttpClientConfiguration::class.java)
    }
}
