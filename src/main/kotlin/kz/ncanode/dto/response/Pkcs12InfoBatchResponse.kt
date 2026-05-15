package kz.ncanode.dto.response

import kz.ncanode.dto.certificate.CertificateInfo
import org.springframework.http.HttpStatus

/**
 * Ответ batch-info для p12. На каждый входной key — один [Item]:
 *  - status 200: key прочитан, cert извлечён, revocation/validity в `signer.valid`.
 *  - status 4xx/5xx: ошибка чтения ключа (битый p12, неверный пароль).
 */
class Pkcs12InfoBatchResponse(
    var results: List<Item> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message) {

    class Item(
        var signer: CertificateInfo? = null,
        status: Int = HttpStatus.OK.value(),
        message: String? = "OK",
    ) : StatusResponse(status, message)
}
