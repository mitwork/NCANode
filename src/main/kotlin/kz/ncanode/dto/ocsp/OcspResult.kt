package kz.ncanode.dto.ocsp

enum class OcspResult {
    /**
     * Ответ responder'а получен, но доверять ему нельзя (битый nonce,
     * несходящаяся подпись, статус != successful) либо responder сам
     * не знает сертификат. Фатален для верификации — fail-closed.
     */
    UNKNOWN,
    ACTIVE,
    REVOKED,

    /**
     * До responder'а не удалось достучаться (сетевая ошибка, таймаут,
     * unparseable body) — ответа нет вовсе. В отличие от [UNKNOWN] допускает
     * деградацию на свежий CRL, если клиент запросил обе проверки
     * (см. `CertificateWrapper.isValid`).
     */
    UNAVAILABLE,
}
