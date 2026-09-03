package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант чтения alias'ов из массива p12-ключей. Одиночный
 * /pkcs12/aliases тоже принимает массив (`keys: List<SignerRequest>`),
 * но падает целиком на первом плохом ключе и не отдаёт частичный результат.
 *
 * Здесь — partial-response: каждый key обрабатывается независимо,
 * получает собственный status + список alias'ов (если успешно прочитан).
 */
class Pkcs12AliasesBatchRequest {
    @NotEmpty
    var keys: List<@Valid SignerRequest> = emptyList()
}
