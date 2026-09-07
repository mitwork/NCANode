package kz.ncanode.dto.certificate

import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
data class CertificateSubject(
    val commonName: String? = null,
    val lastName: String? = null,
    val surName: String? = null,
    val email: String? = null,
    val organization: String? = null,
    val iin: String? = null,
    val bin: String? = null,
    val country: String? = null,
    val locality: String? = null,
    val state: String? = null,
    /**
     * UID (0.9.2342.19200300.100.1.1). У сертификатов шаблона «цифровая
     * система юридического лица» (приказ МИИ РК №522/НҚ) здесь OID самой
     * цифровой системы, в которую разрешено ставить закрытый ключ.
     */
    val uid: String? = null,
    /**
     * businessCategory (2.5.4.15). В шаблоне «участник цифровой системы
     * "Казначейство – Клиент"» (приказ МИИ РК №522/НҚ, приложение 3,
     * структура 6) это обязательное поле с кодом клиента вида `KS01234`.
     */
    val businessCategory: String? = null,
    /**
     * domainComponent (0.9.2342.19200300.100.1.25). В том же шаблоне —
     * обязательное поле с ролью участника вида `ROLE01`.
     */
    val domainComponent: String? = null,
    val dn: String? = null,
)
