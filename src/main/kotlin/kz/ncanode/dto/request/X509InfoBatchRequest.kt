package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [X509InfoRequest]. Отличие от одиночного `/x509/info`
 * (который тоже принимает массив certs): здесь — partial-response,
 * каждый cert получает собственный status вместо одного aggregate'а.
 * Удобно, когда нужно знать *какой именно* cert не распарсился, без
 * парсинга текстового `message` в search-режиме.
 */
class X509InfoBatchRequest : VerifyRequest() {
    @NotEmpty
    var certs: List<String> = emptyList()
}
