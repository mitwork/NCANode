package kz.ncanode.exception

import org.springframework.http.HttpStatus

/**
 * Исключения, возникающие по причине сервера.
 */
class ServerException : ApplicationException {
    constructor(message: String?) : super(message)
    constructor(message: String?, cause: Throwable?) : super(message, cause)

    override val status: Int = HttpStatus.INTERNAL_SERVER_ERROR.value()
}
