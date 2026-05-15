package kz.ncanode

import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.servers.Server
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.cache.annotation.EnableCaching
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.retry.annotation.EnableRetry
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
@EnableCaching
@EnableRetry
open class NCANode {

    @Configuration
    open class OpenApiConfig {
        @Value("\${SWAGGER_RELATIVE_PATH:}")
        private lateinit var swaggerRelativePath: String

        @Bean
        open fun customOpenAPI(): OpenAPI = OpenAPI()
            .addServersItem(Server().url(swaggerRelativePath).description("current server"))
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            println(banner())
            SpringApplication.run(NCANode::class.java, *args)
        }

        @JvmStatic
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
