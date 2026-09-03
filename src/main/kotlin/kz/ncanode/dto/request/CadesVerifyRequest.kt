package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Запрос на проверку CAdES. [data] заполняется только для detached-подписи.
 */
class CadesVerifyRequest : VerifyRequest() {
    @NotEmpty
    var cms: String = ""

    var data: String? = null
}
