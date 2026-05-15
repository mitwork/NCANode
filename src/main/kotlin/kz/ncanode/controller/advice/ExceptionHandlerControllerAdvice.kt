package kz.ncanode.controller.advice

import kz.ncanode.configuration.SystemConfiguration
import kz.ncanode.dto.response.ErrorResponse
import kz.ncanode.exception.ApplicationException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.context.request.WebRequest

@ControllerAdvice
class ExceptionHandlerControllerAdvice(private val systemConfiguration: SystemConfiguration) {

    @ExceptionHandler(RuntimeException::class)
    fun handleRuntimeException(e: RuntimeException, request: WebRequest): ResponseEntity<ErrorResponse> {
        val status = (e as? ApplicationException)?.status ?: HttpStatus.INTERNAL_SERVER_ERROR.value()

        val details = if (systemConfiguration.isDetailedErrors && e.cause != null) e.cause?.message else null

        val response = ErrorResponse(details = details).apply {
            this.status = status
            this.message = e.message
        }

        return ResponseEntity.status(status).body(response)
    }
}
