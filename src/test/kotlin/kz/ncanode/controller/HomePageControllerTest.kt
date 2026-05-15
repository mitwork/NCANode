package kz.ncanode.controller

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.mockk.every
import io.mockk.mockk
import kz.ncanode.service.MaintenanceService
import org.springframework.core.io.ByteArrayResource

/**
 * HomePageController — thin Spring @Controller, рендерит home.html с
 * подстановкой `#{VERSION}` и `#{BANNER}`. Поле `homePage` нормально
 * заполняется Spring'ом через `@Value("classpath:...")`; в unit-тесте
 * подставляем `ByteArrayResource` через reflection — не поднимая context.
 */
class HomePageControllerTest : FunSpec({

    fun makeController(html: String, version: String): HomePageController {
        val maintenance = mockk<MaintenanceService>().apply {
            every { getNCANodeVersion() } returns version
        }
        val controller = HomePageController(maintenance)
        // @Value-инжекция через Spring в unit-тесте недоступна — подставляем поле напрямую.
        HomePageController::class.java.getDeclaredField("homePage").apply {
            isAccessible = true
            set(controller, ByteArrayResource(html.toByteArray()))
        }
        return controller
    }

    test("homePage() substitutes #{VERSION} and #{BANNER} placeholders") {
        val controller = makeController(
            html = "<html>Version: #{VERSION}; Banner=#{BANNER}</html>",
            version = "4.0.0-TEST",
        )

        val rendered = controller.homePage()
        rendered shouldContain "Version: 4.0.0-TEST"
        rendered shouldContain "Banner="
        rendered shouldNotContain "#{VERSION}"
        rendered shouldNotContain "#{BANNER}"
    }

    test("homePage() with null version substitutes empty string for #{VERSION}") {
        // MaintenanceService может вернуть null при build-info-less builds (CLI run).
        val controller = makeController(
            html = "v=#{VERSION}!",
            version = "",  // ниже мок-stub'ить null через let-pattern проще:
        )
        // ручной override на null
        val maintenance = mockk<MaintenanceService>().apply {
            every { getNCANodeVersion() } returns null
        }
        HomePageController::class.java.getDeclaredField("maintenanceService").apply {
            isAccessible = true
            set(controller, maintenance)
        }

        controller.homePage() shouldBe "v=!"
    }
})
