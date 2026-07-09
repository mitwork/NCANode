package kz.ncanode.util

import kz.ncanode.exception.ApplicationException
import org.springframework.http.HttpStatus

/**
 * Partial-batch map: каждый элемент проходит [transform] независимо; при
 * [ApplicationException] или любом другом исключении элемент заменяется на
 * `onError(status, message)` вместо падения всего batch.
 *
 * Централизует обвязку, продублированную во всех batch-методах (batch-инварианты
 * в CLAUDE.md): 200 при успехе, `ApplicationException.status` (400/404/…) при
 * классифицированной ошибке, 500 при неклассифицированной. Ошибка на N-м
 * элементе не валит остальные; порядок сохраняется.
 *
 * `onError` строит доменный error-объект каждого batch'а (`<Op>BatchResponse.Item`
 * для sign-вариантов, `VerificationResponse(valid=false, …)` для verify).
 */
inline fun <T, R> Iterable<T>.mapPartial(
    onError: (status: Int, message: String?) -> R,
    transform: (T) -> R,
): List<R> = map { item ->
    try {
        transform(item)
    } catch (e: ApplicationException) {
        onError(e.status, e.message)
    } catch (e: Exception) {
        onError(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.message)
    }
}
