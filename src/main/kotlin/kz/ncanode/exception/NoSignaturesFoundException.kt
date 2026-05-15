package kz.ncanode.exception

import org.springframework.http.HttpStatus

/**
 * Exception thrown when a PDF document has no digital signatures.
 */
class NoSignaturesFoundException : ApplicationException {
    constructor(message: String?) : super(message)
    constructor(message: String?, cause: Throwable?) : super(message, cause)

    override val status: Int = HttpStatus.NOT_FOUND.value()
}
