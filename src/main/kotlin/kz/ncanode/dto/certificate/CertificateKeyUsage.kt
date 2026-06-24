package kz.ncanode.dto.certificate

enum class CertificateKeyUsage {
    UNKNOWN,
    AUTH,
    SIGN,
    ;

    companion object {
        /**
         * @param keyUsageBits результат `X509Certificate.getKeyUsage()` — `null`,
         *   если расширение keyUsage отсутствует (RFC 5280 §4.2.1.3 — OPTIONAL).
         *   Раньше `null` приводил к NPE на вполне валидном сертификате.
         */
        fun fromKeyUsageBits(keyUsageBits: BooleanArray?): CertificateKeyUsage = when {
            keyUsageBits == null || keyUsageBits.size < 3 -> UNKNOWN
            keyUsageBits[0] && keyUsageBits[1] -> SIGN
            keyUsageBits[0] && keyUsageBits[2] -> AUTH
            else -> UNKNOWN
        }
    }
}
