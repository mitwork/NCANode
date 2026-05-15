package kz.ncanode.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

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
 * Управление: {@code NCANODE_REQUEST_LOG_ENABLED=false} отключает.
 *
 * actuator/swagger-эндпойнты исключены чтобы не засорять лог
 * health-чеками и обращениями к OpenAPI-схеме.
 */
@Slf4j
@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Value("${ncanode.system.requestLog.enabled:true}")
    private boolean enabled;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!enabled) {
            filterChain.doFilter(request, response);
            return;
        }

        long start = System.nanoTime();
        try {
            filterChain.doFilter(request, response);
        } finally {
            long durationMs = (System.nanoTime() - start) / 1_000_000L;
            int status = response.getStatus();
            String format = "{} {} → {} ({}ms)";
            Object[] args = {
                request.getMethod(),
                request.getRequestURI(),
                status,
                durationMs
            };
            if (status >= 500) {
                log.error(format, args);
            } else if (status >= 400) {
                log.warn(format, args);
            } else {
                log.info(format, args);
            }
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null) {
            return false;
        }
        return path.startsWith("/actuator")
            || path.startsWith("/swagger")
            || path.startsWith("/v3/api-docs");
    }
}
