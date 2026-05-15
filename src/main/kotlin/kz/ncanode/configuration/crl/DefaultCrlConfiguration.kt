package kz.ncanode.configuration.crl

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

/**
 * Стандартная конфигурация CRL для запросов (`ncanode.crl.*`).
 */
@Configuration
@ConfigurationProperties(prefix = "ncanode.crl")
@Primary
open class DefaultCrlConfiguration : CrlBaseConfiguration()
