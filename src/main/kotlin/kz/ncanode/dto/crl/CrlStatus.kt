package kz.ncanode.dto.crl

import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import kz.ncanode.dto.certificate.RevocationPolicy
import kz.ncanode.dto.certificate.RevocationResult
import java.util.Date

data class CrlStatus(
    val result: CrlResult? = null,
    val file: String? = null,
    val revocationDate: Date? = null,
    val reason: String? = null,
    /**
     * `true`, если вердикт [CrlResult.ACTIVE] опирается хотя бы на один CRL,
     * актуальный по `nextUpdate` (RFC 5280 §5.1.2.5). Только такой ACTIVE
     * годится как fallback-источник при недоступном OCSP: протухший CRL
     * достаточен для *дополнительной* детекции отзыва в AND-режиме, но не
     * как единственное основание считать сертификат неотозванным.
     */
    val fresh: Boolean = false,
) {
    /**
     * Был ли сертификат в добропорядочном состоянии на момент [signingTime]
     * по данным этого CRL (CAdES-T).
     *
     * `ACTIVE` — да. `REVOKED` — да только если отзыв произошёл строго после
     * [signingTime] и по benign-причине (см. [RevocationPolicy]); `UNAVAILABLE`
     * и отсутствие даты/причины отзыва — консервативно нет (нефатальность
     * UNAVAILABLE в AND-режиме решается в `CertificateWrapper.isValid`).
     */
    fun isValidAt(signingTime: Date): Boolean = when (result) {
        CrlResult.ACTIVE -> true
        CrlResult.REVOKED -> RevocationPolicy.signatureSurvivesRevocation(
            revocationDate,
            RevocationPolicy.reasonFromCrlName(reason),
            signingTime,
        )
        else -> false
    }

    fun toCertificateRevocationStatus(): CertificateRevocationStatus = CertificateRevocationStatus(
        revoked = result == CrlResult.REVOKED,
        revocationTime = revocationDate,
        by = CertificateRevocation.CRL,
        reason = reason,
        result = when (result) {
            CrlResult.ACTIVE -> RevocationResult.ACTIVE
            CrlResult.REVOKED -> RevocationResult.REVOKED
            CrlResult.UNAVAILABLE -> RevocationResult.UNAVAILABLE
            else -> RevocationResult.UNKNOWN
        },
    )
}
