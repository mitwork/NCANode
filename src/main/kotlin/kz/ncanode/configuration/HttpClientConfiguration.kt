package kz.ncanode.configuration

import kz.ncanode.dto.http.HttpProxyConfig
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.config.ConfigurableBeanFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.info.BuildProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import java.net.Authenticator
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.ProxySelector
import java.net.URI
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

@Configuration
@ConfigurationProperties(prefix = "ncanode.http-client")
open class HttpClientConfiguration {
    var proxy: HttpProxyConfig? = null
    var connectTimeout: Int = 5
    var requestTimeout: Int = 30
    var userAgent: String = ""

    /**
     * Потолок размера тела ответа в килобайтах для «мелких» PKI-обменов:
     * OCSP, TSP и загрузка CA-сертификатов. Все они измеряются единицами
     * килобайт, так что дефолтный мегабайт — запас в десятки раз.
     *
     * Нужен потому, что адрес OCSP-респондера в нестрогом режиме берётся из
     * AIA проверяемого сертификата: без потолка такой сертификат заставляет
     * сервер прочитать ответ произвольного размера, причём сразу в кучу.
     * Ноль или меньше — без ограничения.
     *
     * CRL сюда не относится — они на порядки крупнее и ограничены отдельно
     * (`ncanode.crl.maxSizeMb`), к тому же пишутся на диск, а не в память.
     */
    var maxResponseSizeKb: Int = 1024

    // Версия для дефолтного User-Agent берётся из build-info (тот же источник,
    // что и MaintenanceService) — `package.implementationVersion` в boot-jar
    // равен null (классы в BOOT-INF/classes), из-за чего UA всегда был
    // "NCANode/dev". Опционально: если build-info нет (напр. голый unit-контекст),
    // остаётся fallback "dev".
    @Autowired(required = false)
    private var buildProperties: BuildProperties? = null

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
            ?: "NCANode/${buildProperties?.version ?: "dev"}"

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

    /**
     * Заготовка исходящего запроса с уже выставленными total-timeout и
     * непустым User-Agent. Делает инвариант quirk #24 (никогда не слать
     * пустой UA) СТРУКТУРНЫМ: сервисы (Ca/Crl/Ocsp/Tsp) строят запросы через
     * неё и не могут случайно забыть заголовок. Вызывающий добавляет метод
     * (`.GET()` / `.POST(...)`) и, при необходимости, `Content-Type`.
     */
    fun requestBuilder(uri: URI): HttpRequest.Builder =
        HttpRequest.newBuilder(uri)
            .timeout(requestTimeoutDuration)
            .header("User-Agent", effectiveUserAgent)

    /** Потолок тела ответа в байтах; ноль или меньше — без ограничения. */
    private val maxResponseBytes: Long
        get() = if (maxResponseSizeKb <= 0) 0L else maxResponseSizeKb.toLong() * 1024L

    /**
     * Отправляет запрос и читает тело под потолком [maxResponseSizeKb].
     *
     * Почему не `BodyHandlers.ofByteArray()`: он аккумулирует тело целиком и
     * оборвать его нечем — сервер (в т.ч. выбранный чужим сертификатом через
     * AIA) мог бы заставить нас выделить сколько угодно кучи. Здесь тело
     * читается потоково, счётчик проверяется перед добавлением очередного
     * блока, а объявленный `Content-Length` сверх потолка отвергается ещё до
     * чтения тела.
     *
     * Таймаут запроса при этом сохраняется: хотя `send` с `ofInputStream`
     * возвращается по заголовкам, JDK всё равно обрывает обмен по
     * `HttpRequest.timeout` — заблокированный `read` получает
     * `IOException: closed` с корневой причиной `HttpTimeoutException`
     * (проверено). То есть медленный сервер не может держать поток вечно.
     *
     * @throws ResponseTooLargeException если тело превысило потолок
     */
    @Throws(IOException::class, InterruptedException::class)
    fun sendBounded(client: HttpClient, request: HttpRequest): BoundedResponse {
        val maxBytes = maxResponseBytes
        val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())

        return response.body().use { body ->
            val declared = response.headers().firstValueAsLong(CONTENT_LENGTH_HEADER).orElse(-1L)
            if (maxBytes > 0 && declared > maxBytes) {
                throw ResponseTooLargeException(
                    "Response from ${request.uri()} declares $declared bytes, over the $maxBytes byte limit " +
                        "(ncanode.http-client.maxResponseSizeKb)",
                )
            }

            val initialCapacity = if (declared in 0..MAX_PREALLOCATED_BYTES) declared.toInt() else DEFAULT_CAPACITY
            val collected = ByteArrayOutputStream(initialCapacity)
            val chunk = ByteArray(READ_BUFFER_SIZE)
            var total = 0L
            while (true) {
                val read = body.read(chunk)
                if (read < 0) break
                total += read
                if (maxBytes > 0 && total > maxBytes) {
                    throw ResponseTooLargeException(
                        "Response from ${request.uri()} exceeds the $maxBytes byte limit " +
                            "(ncanode.http-client.maxResponseSizeKb)",
                    )
                }
                collected.write(chunk, 0, read)
            }
            BoundedResponse(response.statusCode(), collected.toByteArray())
        }
    }

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

        private const val CONTENT_LENGTH_HEADER = "content-length"
        private const val READ_BUFFER_SIZE = 16 * 1024
        private const val DEFAULT_CAPACITY = 8 * 1024

        /**
         * До какого объявленного размера доверять `Content-Length` при
         * преаллокации буфера. Выше — растём по мере чтения: заголовок
         * приходит от чужого сервера, и верить ему на слово незачем.
         */
        private const val MAX_PREALLOCATED_BYTES = 64L * 1024
    }
}

/**
 * Ответ, тело которого прочитано под потолком
 * (см. [HttpClientConfiguration.sendBounded]).
 */
class BoundedResponse(val statusCode: Int, val body: ByteArray)

/**
 * Тело ответа превысило потолок.
 *
 * Наследник [IOException] намеренно: Ca/Ocsp/Tsp уже ловят его и переводят в
 * свои доменные отказы. Для OCSP это UNAVAILABLE («ответа не было»), а не
 * UNKNOWN — и это корректно по разделению quirk #28: пригодного ответа мы
 * действительно не получили, значит fallback на свежий CRL допустим.
 */
class ResponseTooLargeException(message: String) : IOException(message)
