package kz.ncanode.configuration

import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.service.CrlService
import kz.ncanode.service.DirectoryService
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.scheduling.TaskScheduler
import java.net.http.HttpClient

@Configuration
class CrlBeanConfiguration {

    @Primary
    @Bean
    fun crlService(
        directoryService: DirectoryService,
        crlConfiguration: CrlConfiguration,
        client: HttpClient,
        httpClientConfiguration: HttpClientConfiguration,
        taskScheduler: TaskScheduler,
    ): CrlService = CrlService(
        directoryService, crlConfiguration, client, httpClientConfiguration, taskScheduler, CrlService.CRL_DEFAULT,
    )

    @Qualifier("caCrlService")
    @Bean
    fun caCrlService(
        @Qualifier("caCrlConfiguration") crlConfiguration: CrlConfiguration,
        directoryService: DirectoryService,
        client: HttpClient,
        httpClientConfiguration: HttpClientConfiguration,
        taskScheduler: TaskScheduler,
    ): CrlService = CrlService(
        directoryService, crlConfiguration, client, httpClientConfiguration, taskScheduler, CrlService.CRL_CA,
    )
}
