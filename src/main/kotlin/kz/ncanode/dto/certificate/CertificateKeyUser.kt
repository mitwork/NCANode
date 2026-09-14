package kz.ncanode.dto.certificate

enum class CertificateKeyUser(val oid: String) {
    INDIVIDUAL("1.2.398.3.3.4.1.1"),
    /** Шаблон «цифровая система физического лица» (приказ №522/НҚ). */
    INDIVIDUAL_DIGITAL_SYSTEM("1.2.398.3.3.4.1.1.1"),
    ORGANIZATION("1.2.398.3.3.4.1.2"),
    CEO("1.2.398.3.3.4.1.2.1"),
    CAN_SIGN("1.2.398.3.3.4.1.2.2"),
    CAN_SIGN_FINANCIAL("1.2.398.3.3.4.1.2.3"),
    HR("1.2.398.3.3.4.1.2.4"),
    EMPLOYEE("1.2.398.3.3.4.1.2.5"),
    /** Шаблон «цифровая система юридического лица» (приказ №522/НҚ). */
    ORGANIZATION_DIGITAL_SYSTEM("1.2.398.3.3.4.1.2.6"),
    /** Шаблон «участник цифровой системы "Казначейство – Клиент"». */
    TREASURY_CLIENT("1.2.398.5.19.1.2.2.1"),
    NCA_PRIVILEGES("1.2.398.3.3.4.2"),
    NCA_ADMIN("1.2.398.3.3.4.2.1"),
    NCA_MANAGER("1.2.398.3.3.4.2.2"),
    NCA_OPERATOR("1.2.398.3.3.4.2.3"),
    IDENTIFICATION("1.2.398.3.3.4.3"),
    IDENTIFICATION_CON("1.2.398.3.3.4.3.1"),
    IDENTIFICATION_REMOTE("1.2.398.3.3.4.3.2"),
    IDENTIFICATION_REMOTE_DIGITAL_ID("1.2.398.3.3.4.3.2.1"),
    ;

    companion object {
        fun fromOID(oid: String): CertificateKeyUser? = entries.firstOrNull { it.oid == oid }
    }
}
