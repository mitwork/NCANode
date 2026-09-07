package kz.ncanode.dto.certificate

import com.fasterxml.jackson.annotation.JsonInclude
import java.util.Date

@JsonInclude(JsonInclude.Include.NON_NULL)
data class CertificateInfo(
    val valid: Boolean = false,
    val revocations: List<CertificateRevocationStatus>? = null,
    val notBefore: Date? = null,
    val notAfter: Date? = null,
    val keyUsage: CertificateKeyUsage? = null,
    val serialNumber: String? = null,
    val signAlg: String? = null,
    val keyUser: Set<CertificateKeyUser>? = null,
    /**
     * OID'ы политик применения сертификата (расширение `certificatePolicies`,
     * 2.5.29.32). Публикуются, чтобы проверяющая сторона могла сверить номер
     * политики с условиями её применения — п. 16 Правил формирования и
     * проверки подлинности ЭЦП (приказ МИИ РК №500/НҚ). Сами условия задаёт
     * политика УЦ и из сертификата не выводятся, поэтому мы их не enforce'им.
     */
    val policies: List<String>? = null,
    val publicKey: String? = null,
    val signature: String? = null,
    val subject: CertificateSubject? = null,
    val issuer: CertificateSubject? = null,
)
