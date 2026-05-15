package kz.ncanode.configuration.crl

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

/**
 * Конфигурация CRL для корневых сертификатов (`ncanode.ca.crl.*`).
 */
@Configuration
@ConfigurationProperties(prefix = "ncanode.ca.crl")
@Qualifier("caCrlConfiguration")
open class CaCrlConfiguration : CrlBaseConfiguration()
