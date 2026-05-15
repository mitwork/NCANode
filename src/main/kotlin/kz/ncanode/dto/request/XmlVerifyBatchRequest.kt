package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Batch-проверка XML-подписей: массив XML с общими revocation-флагами
 * (наследуется через [VerifyRequest]). На каждый элемент возвращается
 * отдельный [kz.ncanode.dto.response.VerificationResponse] — клиент
 * сам решает, агрегировать ли valid в AND.
 */
class XmlVerifyBatchRequest : VerifyRequest() {
    @NotEmpty
    var xmls: List<String> = emptyList()
}
