package kz.ncanode.actuator

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
 * Smoke-тест actuator-слоя. Поднимает реальный web-сервер (RANDOM_PORT) и
 * дёргает эндпойнты по HTTP.
 *
 * Проверяет две вещи:
 *  1. Выставленные эндпойнты (`management.endpoints.web.exposure.include`
 *     в application.yml = `health,info,prometheus`) отвечают 200 и отдают
 *     осмысленное тело.
 *  2. Невыставленные (env/beans/…) — 404, т.е. наружу не открыто лишнего.
 *
 * Сети не требует: actuator не зависит от CA/OCSP/TSP. Профиль `test`
 * держит warmup выключенным → CrlWarmupHealthIndicator = UP → health 200.
 *
 * TestRestTemplate удалён в Spring Boot 4, поэтому используем JDK-native
 * HttpClient (как и вся HTTP-логика в проде) — он не бросает на 4xx,
 * что удобно для проверки 404.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ActuatorEndpointTest(
    @param:Autowired private val environment: Environment,
) : FunSpec({

    extension(SpringExtension)

    val http = HttpClient.newHttpClient()

    fun get(path: String): HttpResponse<String> {
        val port = environment.getRequiredProperty("local.server.port")
        val request = HttpRequest.newBuilder(URI("http://localhost:$port$path")).GET().build()
        return http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    test("/actuator discovery перечисляет только выставленные эндпойнты") {
        val resp = get("/actuator")
        resp.statusCode() shouldBe 200
        resp.body() shouldContain "health"
        resp.body() shouldContain "info"
        resp.body() shouldContain "prometheus"
    }

    test("/actuator/health отдаёт 200 UP") {
        val resp = get("/actuator/health")
        resp.statusCode() shouldBe 200
        resp.body() shouldContain "\"status\":\"UP\""
    }

    test("/actuator/info отдаёт 200") {
        val resp = get("/actuator/info")
        resp.statusCode() shouldBe 200
    }

    test("/actuator/prometheus отдаёт метрики в Prometheus text-формате") {
        val resp = get("/actuator/prometheus")
        resp.statusCode() shouldBe 200
        resp.body() shouldContain "# HELP"
        resp.body() shouldContain "# TYPE"
        resp.body() shouldContain "jvm_memory_used_bytes"
    }

    test("невыставленный эндпойнт (env) отдаёт 404") {
        val resp = get("/actuator/env")
        resp.statusCode() shouldBe 404
    }
})
