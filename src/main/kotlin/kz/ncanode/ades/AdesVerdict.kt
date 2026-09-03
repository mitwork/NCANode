package kz.ncanode.ades

import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.certificate.RevocationResult
import java.util.Date

/**
 * Перевод нашей проверки в термины ETSI EN 319 102-1: статус и причина.
 *
 * Флаг `valid` отвечает только «принята или нет», а вопрос обычно другой:
 * подпись **плохая** или её **не удалось проверить**? В первом случае документу
 * верить нельзя, во втором не хватило данных — цепочки, отзыва, сходящейся
 * метки, — и решается это доступом к инфраструктуре, а не переподписанием.
 *
 * Причина выдаётся только доказанная. Там, где по имеющимся данным различить
 * нельзя (например, оборвана ли цепочка), поле остаётся пустым: пустое поле
 * честнее правдоподобной догадки.
 */
object AdesVerdict {

    /** Статус и причина одной подписи. */
    data class Verdict(
        val status: AdesValidationStatus,
        val subIndication: AdesSubIndication? = null,
    )

    /**
     * @param signatureValid вердикт базовой проверки по этому подписанту
     * @param certificates цепочка из проверки; первый — сертификат подписанта
     * @param bindingMatches сошлась ли привязка подписи к сертификату
     * @param claimedLevel уровень, который подпись заявляет
     * @param at момент, на который проверялся сертификат (POE либо «сейчас»)
     * @param revocationRequested запрашивалась ли проверка отзыва
     * @param timestampVerified метка времени подписи прошла проверку
     * @param embeddedUsed вшитый материал оказался авторитетным (уровень LT)
     * @param archiveVerified архивная метка прошла проверку (уровень LTA)
     */
    @Suppress("ReturnCount")
    fun of(
        signatureValid: Boolean,
        certificates: List<CertificateInfo>,
        bindingMatches: Boolean,
        claimedLevel: AdesLevel?,
        at: Date?,
        revocationRequested: Boolean,
        timestampVerified: Boolean = true,
        embeddedUsed: Boolean = true,
        archiveVerified: Boolean = true,
    ): Verdict {
        val signer = certificates.firstOrNull()
            ?: return Verdict(AdesValidationStatus.INVALID, AdesSubIndication.NO_SIGNING_CERTIFICATE_FOUND)

        if (!bindingMatches) {
            return Verdict(AdesValidationStatus.INVALID, AdesSubIndication.CERT_HASH_MISMATCH)
        }

        // Момент подписи доказан меткой — от этого зависит, как читать отзыв.
        val poeProven = claimedLevel != null && claimedLevel.isAtLeast(AdesLevel.T) && timestampVerified

        if (!signer.valid) {
            revokedIndication(signer, poeProven)?.let {
                return Verdict(
                    if (it == AdesSubIndication.CERT_REVOKED) {
                        AdesValidationStatus.INVALID
                    } else {
                        AdesValidationStatus.INDETERMINATE
                    },
                    it,
                )
            }
            if (revocationRequested && revocationUnavailable(signer)) {
                return Verdict(AdesValidationStatus.INDETERMINATE, AdesSubIndication.REVOCATION_DATA_MISSING)
            }
            if (expiredAt(signer, at)) {
                return Verdict(AdesValidationStatus.INDETERMINATE, AdesSubIndication.OUT_OF_BOUNDS_NO_POE)
            }
        }

        if (!signatureValid) {
            // Сертификат в порядке, а подпись не сходится — значит изменилось
            // подписанное содержимое или сама подпись.
            return Verdict(AdesValidationStatus.INVALID, AdesSubIndication.SIG_CRYPTO_FAILURE)
        }

        // Подпись принята. Осталось сказать, если заявленный уровень не
        // подтвердился: сама подпись при этом действительна, но опереться на
        // метку или на вшитый материал нельзя.
        if (claimedLevel != null) {
            if (claimedLevel.isAtLeast(AdesLevel.T) && !timestampVerified) {
                return Verdict(AdesValidationStatus.INDETERMINATE, AdesSubIndication.TIMESTAMP_INVALID)
            }
            if (revocationRequested && claimedLevel.isAtLeast(AdesLevel.LTA) && !archiveVerified) {
                return Verdict(AdesValidationStatus.INDETERMINATE, AdesSubIndication.TIMESTAMP_INVALID)
            }
            if (revocationRequested && claimedLevel.isAtLeast(AdesLevel.LT) && !embeddedUsed) {
                return Verdict(AdesValidationStatus.INDETERMINATE, AdesSubIndication.REVOCATION_DATA_MISSING)
            }
        }

        return Verdict(AdesValidationStatus.VALID)
    }

    /** Итог по документу — худший из вердиктов подписей. */
    fun worst(verdicts: List<Verdict>): Verdict? = verdicts.minByOrNull {
        when (it.status) {
            AdesValidationStatus.INVALID -> 0
            AdesValidationStatus.INDETERMINATE -> 1
            AdesValidationStatus.VALID -> 2
        }
    }

    /**
     * Отзыв: если подпись сделана до него и это доказано меткой, наш
     * `isValid` его прощает и сюда мы не попадаем. Значит либо отзыв
     * состоялся раньше подписи, либо доказать обратное нечем.
     */
    private fun revokedIndication(signer: CertificateInfo, poeProven: Boolean): AdesSubIndication? {
        val revoked = signer.revocations?.any { it.revoked } ?: false
        if (!revoked) return null
        return if (poeProven) AdesSubIndication.CERT_REVOKED else AdesSubIndication.REVOKED_NO_POE
    }

    private fun revocationUnavailable(signer: CertificateInfo): Boolean {
        val revocations = signer.revocations
        if (revocations.isNullOrEmpty()) return true
        return revocations.all { it.result == RevocationResult.UNAVAILABLE || it.result == null }
    }

    private fun expiredAt(signer: CertificateInfo, at: Date?): Boolean {
        val moment = at ?: Date()
        val notBefore = signer.notBefore
        val notAfter = signer.notAfter
        return (notAfter != null && notAfter.before(moment)) || (notBefore != null && notBefore.after(moment))
    }
}
