package kz.ncanode.exception

import org.springframework.http.HttpStatus

/**
 * Исключения, возникающие по ошибке клиента.
 */
class ClientException : ApplicationException {
    constructor(message: String?) : super(message)
    constructor(message: String?, cause: Throwable?) : super(message, cause)

    override val status: Int = HttpStatus.BAD_REQUEST.value()
}
