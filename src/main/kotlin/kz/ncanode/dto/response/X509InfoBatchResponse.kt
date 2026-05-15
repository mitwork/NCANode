package kz.ncanode.dto.response

import kz.ncanode.dto.certificate.CertificateInfo
import org.springframework.http.HttpStatus

/**
 * Ответ batch-info для X.509. На каждый входной cert — один [Item]:
 *  - status 200: cert успешно распарсен; revocation/validity отражены
 *    в `signer.valid` (бизнес-уровень — может быть false для expired/revoked).
 *  - status 400/500: cert не удалось распарсить (формат / провайдер).
 */
class X509InfoBatchResponse(
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
