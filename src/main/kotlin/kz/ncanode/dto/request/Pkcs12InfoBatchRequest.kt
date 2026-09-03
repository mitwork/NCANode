package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [Pkcs12InfoRequest]: partial-response для проверки массива p12-ключей.
 * Ошибка в одном ключе (неверный пароль, битый p12) не валит остальных —
 * каждый key получает собственный status.
 */
class Pkcs12InfoBatchRequest : VerifyRequest() {
    @NotEmpty
    var keys: List<@Valid SignerRequest> = emptyList()
}
