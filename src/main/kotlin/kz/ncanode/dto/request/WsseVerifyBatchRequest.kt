package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-вариант [WsseVerifyRequest]. Сейчас идентичен по форме
 * [XmlVerifyBatchRequest], но вынесен отдельно по той же причине, что
 * и одиночный — чтобы оставить возможность WSSE-специфичных опций.
 */
class WsseVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    var xmls: List<String> = emptyList()
}
