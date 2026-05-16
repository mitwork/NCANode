package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty

/**
 * Запрос на верификацию подписанного SOAP-конверта.
 *
 * Семантически близок к [XmlVerifyRequest] (тот же `xml` + общий
 * `revocationCheck`), но вынесен отдельным классом — чтобы будущие
 * WSSE-специфичные опции (например, mustUnderstand, actor, конкретный
 * `wsu:Id` для проверки конкретной части envelope'а) не пришлось
 * протаскивать через XML-side API.
 */
class WsseVerifyRequest : VerifyRequest() {
    @NotEmpty
    var xml: String = ""
}
