package kz.ncanode.oid

/**
 * Стандартные (не-NCA-специфичные) Extended Key Usage OID'ы,
 * которые используются в NCA-сертификатах наряду с собственными NCA-OID'ами.
 *
 * Источник: RFC 5280 §4.2.1.12, RFC 3161, RFC 6960.
 */
object KnownEkus {

    /**
     * id-kp-serverAuth — `1.3.6.1.5.5.7.3.1`.
     * Сервер в TLS-handshake. В NCA-сертификатах не используется,
     * приведён для полноты.
     */
    const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

    /**
     * id-kp-clientAuth — `1.3.6.1.5.5.7.3.2`.
     * Клиент в TLS-handshake. Используется во ВСЕХ NCA-сертификатах
     * (Individual/Employee/CEO, и Auth, и Sign — даже в Sign-сертификатах,
     * что необычно, но это NCA-конвенция).
     */
    const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

    /**
     * id-kp-codeSigning — `1.3.6.1.5.5.7.3.3`.
     * Подпись программного кода. В NCA не используется.
     */
    const val CODE_SIGNING = "1.3.6.1.5.5.7.3.3"

    /**
     * id-kp-emailProtection — `1.3.6.1.5.5.7.3.4`.
     * S/MIME-подпись писем. NCA использует **только** в Individual Sign.
     */
    const val EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"

    /**
     * id-kp-timeStamping — `1.3.6.1.5.5.7.3.8`. Critical для TSA.
     * RFC 3161 §2.3 — сертификат TSA ОБЯЗАН содержать его в EKU.
     */
    const val TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

    /**
     * id-kp-OCSPSigning — `1.3.6.1.5.5.7.3.9`. Critical для OCSP responder.
     * RFC 6960 §4.2.2.2 — делегированный OCSP-responder обязан иметь
     * его в EKU, иначе валидаторы (включая исправленный NCANode) откажутся
     * доверять подписи на OCSP-ответе.
     */
    const val OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
}
