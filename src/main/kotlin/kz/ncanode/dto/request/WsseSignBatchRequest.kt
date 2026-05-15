package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [WsseSignRequest]: подписывает массив SOAP envelope'ов
 * одним и тем же ключом. WSSE — один signer per envelope (в отличие от
 * XML/CMS, где `signers` это список); это соответствие сохраняется в
 * batch'е: key/password — на весь batch.
 */
class WsseSignBatchRequest {
    @NotEmpty
    var xmls: List<String> = emptyList()

    @NotEmpty
    var key: String = ""

    @NotEmpty
    var password: String = ""

    var keyAlias: String? = null

    var isTrimXml: Boolean = false
}
