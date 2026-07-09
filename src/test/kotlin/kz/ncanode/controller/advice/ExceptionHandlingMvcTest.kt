package kz.ncanode.controller.advice

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.env.Environment
import org.springframework.test.context.ActiveProfiles
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * End-to-end проверка маршрутизации исключений через реальный Spring MVC
 * (аудит H2). Поднимает web-сервер, шлёт битые/невалидные тела по HTTP.
 *
 * До фикса `@ExceptionHandler(RuntimeException)` ловил
 * `HttpMessageNotReadableException` (это RuntimeException) → отдавал 500 на
 * битый JSON; `MethodArgumentNotValidException` (не RuntimeException) не
 * ловился вовсе → 400 дефолтным Boot-телом мимо `ErrorResponse`. Теперь оба —
 * 400 в форме `ErrorResponse` (`status`/`message`).
 *
 * Сети не требует: парсинг/валидация падают до сервисной логики.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ExceptionHandlingMvcTest(
    @param:Autowired private val environment: Environment,
) : FunSpec({

    extension(SpringExtension)

    val http = HttpClient.newHttpClient()

    fun postJson(path: String, body: String): HttpResponse<String> {
        val port = environment.getRequiredProperty("local.server.port")
        val request = HttpRequest.newBuilder(URI("http://localhost:$port$path"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        return http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    test("malformed JSON body → 400 in ErrorResponse shape (not 500)") {
        val resp = postJson("/x509/info", "{ this is not json")
        resp.statusCode() shouldBe 400
        resp.body() shouldContain "\"status\":400"
        resp.body() shouldContain "\"message\""
    }

    test("type mismatch (certs is not an array) → 400") {
        val resp = postJson("/x509/info", "{\"certs\":\"should-be-array\"}")
        resp.statusCode() shouldBe 400
        resp.body() shouldContain "\"status\":400"
    }

    test("bean validation failure (@NotEmpty empty batch) → 400 in ErrorResponse with field name") {
        val resp = postJson("/x509/info/batch", "{\"certs\":[]}")
        resp.statusCode() shouldBe 400
        resp.body() shouldContain "\"status\":400"
        resp.body() shouldContain "certs"
    }

    test("@Valid cascade: signer with empty key/password → 400 (validation before crypto)") {
        // Раньше пустой key проходил валидацию (нет @Valid-каскада) и падал в
        // Kalkan → 500. Теперь @Valid на signers каскадит @NotEmpty key/password.
        val resp = postJson("/xml/sign", "{\"xml\":\"<a/>\",\"signers\":[{}]}")
        resp.statusCode() shouldBe 400
        resp.body() shouldContain "\"status\":400"
    }

    test("@Valid cascade: PDF signer with missing 'signer' object → 400 (not lateinit 500)") {
        // Раньше lateinit signer → UninitializedPropertyAccessException → 500.
        // Теперь @NotNull @Valid + @Valid на списке → валидация ловит как 400.
        val resp = postJson("/pdf/sign", "{\"pdf\":\"AAAA\",\"signers\":[{}]}")
        resp.statusCode() shouldBe 400
        resp.body() shouldContain "\"status\":400"
    }
})
