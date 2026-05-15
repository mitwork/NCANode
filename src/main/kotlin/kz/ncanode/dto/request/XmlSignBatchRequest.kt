package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [XmlSignRequest]: подписывает массив XML одним и тем же
 * набором signer'ов. Mass-signing use case (upstream issue malikzh/NCANode#212):
 * клиент шлёт один POST вместо N подряд.
 *
 * Семантика partial-response — на каждый XML отдаём отдельный результат
 * со своим status'ом, ошибка на N-м item'е не валит остальные. Подробнее —
 * в [kz.ncanode.dto.response.XmlSignBatchResponse].
 */
class XmlSignBatchRequest {
    @NotEmpty
    var xmls: List<String> = emptyList()

    @NotEmpty
    var signers: List<SignerRequest> = emptyList()

    var isClearSignatures: Boolean = false

    var isTrimXml: Boolean = false
}
