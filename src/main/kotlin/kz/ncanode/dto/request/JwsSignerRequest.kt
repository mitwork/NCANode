package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Подписант JWS: ключ и алгоритм, которым он подписывает.
 *
 * Алгоритм задаётся явно, а не выводится из сертификата: ключ может
 * поддерживать несколько, и выбор — за клиентом (`GG2015`, `GG2004`,
 * `ES256/384/512`, `RS256/384/512`).
 */
class JwsSignerRequest {
    @NotEmpty
    var alg: String = ""

    @NotEmpty
    var key: String = ""

    @NotEmpty
    var password: String = ""

    var keyAlias: String? = null
}
