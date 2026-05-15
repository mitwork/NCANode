package kz.ncanode.dto.certificate

enum class CertificateKeyUsage {
    UNKNOWN,
    AUTH,
    SIGN,
    ;

    companion object {
        @JvmStatic
        fun fromKeyUsageBits(keyUsageBits: BooleanArray): CertificateKeyUsage = when {
            keyUsageBits[0] && keyUsageBits[1] -> SIGN
            keyUsageBits[0] && keyUsageBits[2] -> AUTH
            else -> UNKNOWN
        }
    }
}
