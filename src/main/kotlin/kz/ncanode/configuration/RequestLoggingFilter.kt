package kz.ncanode.configuration

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Логирует каждый HTTP-запрос: метод, URI, статус, длительность в миллисекундах.
 *
 * Без этого фильтра в логах NCANode не видно входящих запросов — нельзя
 * отследить, что приложение реально получает, как часто, с какой latency.
 *
 * Уровень логирования зависит от статус-кода:
 *  - 5xx → ERROR (серверная ошибка, требует внимания);
 *  - 4xx → WARN (клиентская ошибка);
 *  - остальное → INFO.
 *
 * Управление: `NCANODE_REQUEST_LOG_ENABLED=false` отключает.
 *
 * actuator/swagger-эндпойнты исключены чтобы не засорять лог
 * health-чеками и обращениями к OpenAPI-схеме.
 */
@Component
class RequestLoggingFilter : OncePerRequestFilter() {

    @Value("\${ncanode.system.requestLog.enabled:true}")
    private var enabled: Boolean = true

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (!enabled) {
            filterChain.doFilter(request, response)
            return
        }

        val start = System.nanoTime()
        try {
            filterChain.doFilter(request, response)
        } finally {
            val durationMs = (System.nanoTime() - start) / 1_000_000L
            val status = response.status
            val format = "{} {} → {} ({}ms)"
            val args = arrayOf<Any>(request.method, request.requestURI, status, durationMs)
            when {
                status >= 500 -> log.error(format, *args)
                status >= 400 -> log.warn(format, *args)
                else -> log.info(format, *args)
            }
        }
    }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val path = request.requestURI ?: return false
        return path.startsWith("/actuator")
            || path.startsWith("/swagger")
            || path.startsWith("/v3/api-docs")
    }

    companion object {
        private val log = LoggerFactory.getLogger(RequestLoggingFilter::class.java)
    }
}
