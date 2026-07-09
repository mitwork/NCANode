package kz.ncanode.controller.advice

import kz.ncanode.configuration.SystemConfiguration
import kz.ncanode.dto.response.ErrorResponse
import kz.ncanode.exception.ApplicationException
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.context.request.WebRequest

@ControllerAdvice
class ExceptionHandlerControllerAdvice(private val systemConfiguration: SystemConfiguration) {

    /**
     * Наши классифицированные ошибки: status берётся из подкласса
     * (ClientException=400 / NoSignaturesFoundException=404 / ServerException=500).
     * `message` мы формируем сами — утечки внутренних деталей нет.
     * Серверные (5xx) логируем как реальный сбой.
     */
    @ExceptionHandler(ApplicationException::class)
    fun handleApplicationException(e: ApplicationException): ResponseEntity<ErrorResponse> {
        if (e.status >= HttpStatus.INTERNAL_SERVER_ERROR.value()) {
            log.error("Application error ({}): {}", e.status, e.message, e)
        }
        return errorResponse(e.status, e.message, e.cause)
    }

    /**
     * Клиент прислал НЕЧИТАЕМОЕ/НЕВАЛИДНОЕ тело — это 400, не 500.
     *  - [HttpMessageNotReadableException] — битый JSON, неверный тип/enum,
     *    null в non-null поле (Jackson MismatchedInput).
     *  - [MethodArgumentNotValidException] — bean-валидация @RequestBody
     *    (@NotEmpty/@Valid): в message перечисляем упавшие поля.
     *
     * Более специфичные хендлеры, чем [handleUnexpected], поэтому Spring
     * выбирает их для этих исключений. Сырой текст Jackson клиенту не отдаём —
     * только под detailedErrors в `details`.
     */
    @ExceptionHandler(HttpMessageNotReadableException::class, MethodArgumentNotValidException::class)
    fun handleBadRequest(e: Exception): ResponseEntity<ErrorResponse> {
        val message = when (e) {
            is MethodArgumentNotValidException ->
                e.bindingResult.fieldErrors
                    .joinToString("; ") { "${it.field}: ${it.defaultMessage ?: "invalid"}" }
                    .ifEmpty { "Validation failed" }
            else -> "Malformed request body"
        }
        val cause = if (systemConfiguration.isDetailedErrors) e else null
        return errorResponse(HttpStatus.BAD_REQUEST.value(), message, cause)
    }

    /**
     * Всё непредвиденное (не наш [ApplicationException] и не разобранная выше
     * клиентская ошибка) — 500. Логируем ПОЛНОСТЬЮ (иначе инцидент не
     * диагностировать по логам), клиенту отдаём обобщённое сообщение, чтобы не
     * утекали внутренности (helpful-NPE с именами полей, пути парсера). Под
     * detailedErrors можно вернуть реальный текст.
     *
     * ВАЖНО: ловим именно [RuntimeException], а НЕ [Exception] — иначе перехватим
     * штатные Spring MVC исключения (405/415/…), которые сами несут правильный
     * статус, и превратим их в 500.
     */
    @ExceptionHandler(RuntimeException::class)
    fun handleUnexpected(e: RuntimeException): ResponseEntity<ErrorResponse> {
        log.error("Unhandled exception", e)
        val message = if (systemConfiguration.isDetailedErrors) e.message else "Internal server error"
        return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), message, e.cause)
    }

    private fun errorResponse(status: Int, message: String?, cause: Throwable?): ResponseEntity<ErrorResponse> {
        val details = if (systemConfiguration.isDetailedErrors && cause != null) cause.message else null
        val response = ErrorResponse(details = details).apply {
            this.status = status
            this.message = message
        }
        return ResponseEntity.status(status).body(response)
    }

    companion object {
        private val log = LoggerFactory.getLogger(ExceptionHandlerControllerAdvice::class.java)
    }
}
