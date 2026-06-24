package kz.ncanode.dto.certificate

import java.security.cert.CRLReason
import java.util.Date

/**
 * Политика влияния отзыва сертификата на валидность подписи с доказанным
 * временем существования (CAdES-T).
 *
 * Подпись остаётся валидной, если сертификат был отозван **строго позже**
 * момента её постановки (доказанного TSP-меткой) и по «benign»
 * административной причине — на момент подписи сертификат был
 * добропорядочным, а отзыв лишь вывел его из обращения.
 *
 * Отзыв по компрометации ключа/CA трактуется **ретроактивно**: скомпрометированному
 * ключу нельзя верить и до формального отзыва, поэтому подпись считается
 * невалидной независимо от времени отзыва. Так же консервативно (как
 * невалидные) трактуются `unspecified`, `certificateHold` и отсутствие
 * причины — там, где намерение CA неоднозначно, безопаснее отклонить.
 *
 * RFC 5280 §5.3.1 (reason codes), ETSI EN 319 102-1 (past signature validation).
 */
object RevocationPolicy {

    /**
     * Причины отзыва, при которых подпись, поставленная ДО отзыва, остаётся
     * валидной. Всё, чего здесь нет (компрометация, hold, unspecified,
     * неизвестная причина), обесценивает подпись ретроактивно.
     */
    private val BENIGN_REASONS = setOf(
        CRLReason.AFFILIATION_CHANGED,
        CRLReason.SUPERSEDED,
        CRLReason.CESSATION_OF_OPERATION,
        CRLReason.PRIVILEGE_WITHDRAWN,
    )

    /**
     * Переживёт ли подпись с доказанным временем [signingTime] отзыв
     * сертификата в момент [revocationTime] по причине [reason].
     *
     * @return `true`, только если отзыв случился строго после [signingTime]
     *   и причина входит в [BENIGN_REASONS]. `null` revocationTime/reason →
     *   `false` (консервативно).
     */
    fun signatureSurvivesRevocation(revocationTime: Date?, reason: CRLReason?, signingTime: Date): Boolean {
        if (revocationTime == null) return false
        // Отзыв в момент подписи или раньше — сертификат уже не был добропорядочным.
        if (!revocationTime.after(signingTime)) return false
        return reason in BENIGN_REASONS
    }

    /**
     * OCSP отдаёт причину int-кодом RFC 5280 §5.3.1, который совпадает с
     * ordinal [CRLReason] 1:1 (UNSPECIFIED=0 … AA_COMPROMISE=10). Код `-1`
     * (причина отсутствовала в ответе) и любой вне диапазона → `null`.
     */
    fun reasonFromOcspCode(code: Int): CRLReason? {
        if (code < 0) return null
        return CRLReason.entries.getOrNull(code)
    }

    /**
     * CRL-entry отдаёт причину именем enum [CRLReason] (см.
     * `X509CRLEntry.getRevocationReason()`); пустая строка или
     * нераспознанное имя → `null`.
     */
    fun reasonFromCrlName(name: String?): CRLReason? {
        if (name.isNullOrBlank()) return null
        return try {
            CRLReason.valueOf(name)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
