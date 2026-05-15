package kz.ncanode.service

import jakarta.annotation.PostConstruct
import org.slf4j.LoggerFactory
import org.springframework.boot.info.BuildProperties
import org.springframework.stereotype.Service

@Service
class MaintenanceService(private val buildProperties: BuildProperties) {

    fun getNCANodeVersion(): String? = buildProperties.version

    @PostConstruct
    fun displayVersion() {
        log.info("NCANode version: {}", getNCANodeVersion())
    }

    companion object {
        private val log = LoggerFactory.getLogger(MaintenanceService::class.java)
    }
}
