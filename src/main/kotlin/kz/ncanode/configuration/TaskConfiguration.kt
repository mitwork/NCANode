package kz.ncanode.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.TaskScheduler
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler

@Configuration
class TaskConfiguration {
    @Bean
    fun taskScheduler(): TaskScheduler = ThreadPoolTaskScheduler().apply {
        poolSize = 10
        setThreadNamePrefix("ThreadPoolTaskScheduler")
    }
}
