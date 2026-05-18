package kz.ncanode

import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.info.License
import io.swagger.v3.oas.models.servers.Server
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
open class NCANode {

    @Configuration
    open class OpenApiConfig {
        @Value("\${SWAGGER_RELATIVE_PATH:}")
        private lateinit var swaggerRelativePath: String

        @Bean
        open fun customOpenAPI(): OpenAPI = OpenAPI()
            .info(
                Info()
                    .title("NCANode API")
                    .version("v4")
                    .description(
                        """
                        Server-side подпись и верификация для ЭЦП НУЦ РК (gosrk).

                        Интегрируется с НУЦ-инфраструктурой: pki.gov.kz / test.pki.gov.kz
                        (OCSP/TSP/CRL). Поддерживает GOST 34.10-2015 (актуальный стандарт),
                        форматы CMS/CAdES-T, XMLDSIG, PAdES, WS-Security, JWT.

                        Каждая операция доступна в одиночном (`/<service>/<op>`)
                        и batch (`/<service>/<op>/batch`) вариантах.
                        """.trimIndent()
                    )
                    .license(License().name("MIT").url("https://github.com/malikzh/NCANode/blob/master/LICENSE"))
            )
            .addServersItem(Server().url(swaggerRelativePath).description("current server"))
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            println(banner())
            SpringApplication.run(NCANode::class.java, *args)
        }

        fun banner(): String = """
            888b    888  .d8888b.        d8888 888b    888  .d88888b.  8888888b.  8888888888  d8888  ${" "}
            8888b   888 d88P  Y88b      d88888 8888b   888 d88P" "Y88b 888  "Y88b 888        d8P888  ${" "}
            88888b  888 888    888     d88P888 88888b  888 888     888 888    888 888       d8P 888  ${" "}
            888Y88b 888 888           d88P 888 888Y88b 888 888     888 888    888 8888888  d8P  888  ${" "}
            888 Y88b888 888          d88P  888 888 Y88b888 888     888 888    888 888     d88   888  ${" "}
            888  Y88888 888    888  d88P   888 888  Y88888 888     888 888    888 888     8888888888 ${" "}
            888   Y8888 Y88b  d88P d8888888888 888   Y8888 Y88b. .d88P 888  .d88P 888           888  ${" "}
            888    Y888  "Y8888P" d88P     888 888    Y888  "Y88888P"  8888888P"  8888888888    888 ${" "}
        """.trimIndent()
    }
}
