package kz.ncanode.configuration

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.xmldsig.KncaXS
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.security.Security

@Configuration
class KalkanConfiguration {

    @Bean
    fun kalkanProvider(): KalkanProvider {
        log.info("KalkanCrypt version: {}", KalkanProvider::class.java.`package`.implementationVersion)
        val provider = KalkanProvider()
        Security.addProvider(provider)
        KncaXS.loadXMLSecurity()
        return provider
    }

    companion object {
        private val log = LoggerFactory.getLogger(KalkanConfiguration::class.java)
    }
}
