package kz.ncanode.configuration

import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.service.CrlService
import kz.ncanode.service.DirectoryService
import org.apache.http.impl.client.CloseableHttpClient
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.scheduling.TaskScheduler

@Configuration
class CrlBeanConfiguration {

    @Primary
    @Bean
    fun crlService(
        directoryService: DirectoryService,
        crlConfiguration: CrlConfiguration,
        client: CloseableHttpClient,
        taskScheduler: TaskScheduler,
    ): CrlService = CrlService(directoryService, crlConfiguration, client, taskScheduler, CrlService.CRL_DEFAULT)

    @Qualifier("caCrlService")
    @Bean
    fun caCrlService(
        @Qualifier("caCrlConfiguration") crlConfiguration: CrlConfiguration,
        directoryService: DirectoryService,
        client: CloseableHttpClient,
        taskScheduler: TaskScheduler,
    ): CrlService = CrlService(directoryService, crlConfiguration, client, taskScheduler, CrlService.CRL_CA)
}
