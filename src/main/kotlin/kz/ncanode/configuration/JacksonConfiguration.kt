package kz.ncanode.configuration

import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/**
 * Регистрирует Jackson 2 как первый JSON HttpMessageConverter — но
 * ограниченный нашими DTO-классами (`kz.ncanode.dto.*`).
 *
 * Spring Boot 4 авто-конфигурит Jackson 3 (tools.jackson.core) как default
 * ObjectMapper. Существующие Java DTO используют Lombok `@Jacksonized`,
 * который генерирует Jackson 2 аннотации (com.fasterxml.jackson.*).
 * Jackson 3 эти аннотации не распознаёт → 500 "Type definition error".
 *
 * Поэтому Jackson 2 обрабатывает только наши DTO; всё остальное
 * (byte[] от springdoc, String, статика) идёт через default-конвертеры
 * Spring Boot. Без `isOurDto` фильтра Jackson 2 перехватывал бы byte[]
 * от `/v3/api-docs` и кодировал его в base64.
 *
 * Уйдёт целиком когда все DTO будут портированы в Kotlin data classes
 * (Jackson 3 поймёт их нативно через jackson-module-kotlin).
 */
@Configuration
@Suppress("removal", "DEPRECATION")
class JacksonConfiguration : WebMvcConfigurer {

    override fun extendMessageConverters(converters: MutableList<HttpMessageConverter<*>>) {
        converters.add(0, NcanodeJackson2Converter())
    }

    private class NcanodeJackson2Converter : MappingJackson2HttpMessageConverter() {
        private fun isOurDto(clazz: Class<*>): Boolean =
            clazz.name.startsWith("kz.ncanode.dto.")

        override fun canRead(clazz: Class<*>, mediaType: MediaType?): Boolean =
            isOurDto(clazz) && super.canRead(clazz, mediaType)

        override fun canWrite(clazz: Class<*>, mediaType: MediaType?): Boolean =
            isOurDto(clazz) && super.canWrite(clazz, mediaType)
    }
}
