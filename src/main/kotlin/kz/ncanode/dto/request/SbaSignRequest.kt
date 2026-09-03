package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull

/**
 * Подпись произвольных данных ключом — без контейнера (SIGN_BYTES_ARRAY).
 *
 * Парная операция к `/x509/verify`: там на вход идут сертификат, подпись и
 * данные, здесь — ключ и данные. [data] трактуется как строка в UTF-8, ровно
 * как при проверке; иначе пара «подписал — проверил» не сошлась бы.
 */
class SbaSignRequest {
    @NotEmpty
    var data: String = ""

    @NotNull
    @Valid
    var signer: SignerRequest? = null
}
