package kz.ncanode.configuration

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * Потолок размера ответа для «мелких» PKI-обменов (OCSP, TSP, CA).
 *
 * Нужен потому, что адрес OCSP-респондера в нестрогом режиме берётся из AIA
 * проверяемого сертификата: без потолка автор сертификата решал бы, сколько
 * памяти мы выделим на ответ. CRL сюда не относится — они ограничены
 * отдельно и пишутся на диск.
 */
class HttpClientConfigurationTest : FunSpec({

    val uri = URI("http://ocsp.example.kz/")

    fun response(body: InputStream, status: Int = 200, contentLength: Long? = null): HttpResponse<InputStream> {
        val headers = if (contentLength == null) {
            HttpHeaders.of(emptyMap()) { _, _ -> true }
        } else {
            HttpHeaders.of(mapOf("content-length" to listOf(contentLength.toString()))) { _, _ -> true }
        }
        return mockk<HttpResponse<InputStream>>(relaxed = true).apply {
            every { statusCode() } returns status
            every { body() } returns body
            every { this@apply.headers() } returns headers
        }
    }

    fun clientReturning(response: HttpResponse<InputStream>): HttpClient =
        mockk<HttpClient>(relaxed = true).apply {
            every { send(any(), any<HttpResponse.BodyHandler<InputStream>>()) } returns response
        }

    fun request(configuration: HttpClientConfiguration): HttpRequest =
        configuration.requestBuilder(uri).GET().build()

    test("reads a body that fits and preserves the status code") {
        val configuration = HttpClientConfiguration()
        val payload = "ocsp response".toByteArray()
        val client = clientReturning(response(ByteArrayInputStream(payload), status = 200))

        val bounded = configuration.sendBounded(client, request(configuration))

        bounded.statusCode shouldBe 200
        bounded.body.contentEquals(payload) shouldBe true
    }

    test("aborts a body that grows past the limit") {
        // Content-Length не объявлен — превышение видно только по ходу чтения.
        val configuration = HttpClientConfiguration().apply { maxResponseSizeKb = 1 }
        val client = clientReturning(response(ByteArrayInputStream(ByteArray(256 * 1024))))

        val failure = shouldThrow<ResponseTooLargeException> {
            configuration.sendBounded(client, request(configuration))
        }
        failure.message!! shouldContain "exceeds"
    }

    test("refuses an oversized Content-Length without reading the body") {
        val configuration = HttpClientConfiguration().apply { maxResponseSizeKb = 64 }
        // Если тело всё-таки прочитают — тест упадёт здесь, а не пройдёт тихо.
        val forbidden = object : InputStream() {
            override fun read(): Int = error("body must not be read")
            override fun read(b: ByteArray, off: Int, len: Int): Int = error("body must not be read")
        }
        val client = clientReturning(response(forbidden, contentLength = 512L * 1024 * 1024))

        val failure = shouldThrow<ResponseTooLargeException> {
            configuration.sendBounded(client, request(configuration))
        }
        failure.message!! shouldContain "declares"
    }

    test("does not limit anything when maxResponseSizeKb is not positive") {
        val configuration = HttpClientConfiguration().apply { maxResponseSizeKb = 0 }
        val payload = ByteArray(256 * 1024)
        val client = clientReturning(response(ByteArrayInputStream(payload)))

        configuration.sendBounded(client, request(configuration)).body.size shouldBe payload.size
    }

    test("keeps sending the non-empty User-Agent required by upstream filters") {
        // Инвариант quirk #24: пустой UA ловится фильтрами на пути к pki.gov.kz.
        // sendBounded не подменяет сборку запроса, но проверяем совместно —
        // именно этой парой методов пользуются все PKI-сервисы.
        val configuration = HttpClientConfiguration()
        request(configuration).headers().firstValue("User-Agent").orElse("") shouldContain "NCANode/"
    }
})
