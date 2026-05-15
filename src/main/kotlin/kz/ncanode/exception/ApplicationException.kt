package kz.ncanode.exception

abstract class ApplicationException : RuntimeException {
    protected constructor(message: String?) : super(message)
    protected constructor(message: String?, cause: Throwable?) : super(message, cause)

    abstract val status: Int
}
