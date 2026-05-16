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
             ____  _____   ______       _       ____  _____               __          ______  ${" "}
            |_   \|_   _|.' ___  |     / \     |_   \|_   _|             |  ]        / ____ `.${" "}
              |   \ | | / .'   \_|    / _ \      |   \ | |   .--.    .--.| | .---.   `'  __) |${" "}
              | |\ \| | | |          / ___ \     | |\ \| | / .'`\ \/ /'`\' |/ /__\\  _  |__ '.${" "}
             _| |_\   |_\ `.___.'\ _/ /   \ \_  _| |_\   |_| \__. || \__/  || \__., | \____) |${" "}
            |_____|\____|`.____ .'|____| |____||_____|\____|'.__.'  '.__.;__]'.__.'  \______.'${" "}
            """.trimIndent()
    }
}
