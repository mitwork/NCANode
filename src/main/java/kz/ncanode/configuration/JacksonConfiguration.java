package kz.ncanode.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Регистрирует Jackson 2 как первый JSON HttpMessageConverter.
 *
 * Spring Boot 4 авто-конфигурит Jackson 3 (tools.jackson.core) как default
 * ObjectMapper. Существующие Java DTO (CmsVerifyRequest и др.) используют
 * Lombok @Jacksonized, который генерирует Jackson 2 аннотации
 * (com.fasterxml.jackson.databind.annotation.JsonDeserialize). Jackson 3
 * эти аннотации не распознаёт — получается 500 "Type definition error".
 *
 * Spring Framework 7 сохранил MappingJackson2HttpMessageConverter для
 * обратной совместимости — регистрируем его на индекс 0, чтобы он обрабатывал
 * application/json первее Jackson 3'шного.
 *
 * Уйдёт когда все DTO будут портированы в Kotlin data classes (Jackson 3
 * понимает их через kotlin-module нативно).
 */
@Configuration
public class JacksonConfiguration implements WebMvcConfigurer {

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(0, new MappingJackson2HttpMessageConverter());
    }
}
