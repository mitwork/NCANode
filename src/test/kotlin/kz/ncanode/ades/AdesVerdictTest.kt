package kz.ncanode.ades

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import kz.ncanode.dto.certificate.RevocationResult
import java.util.Date

/**
 * Перевод вердикта в термины ETSI EN 319 102-1.
 *
 * Смысл различения — практический: «подпись плохая» и «подпись не удалось
 * проверить» требуют разных действий, а флаг `valid` их уравнивает. Здесь
 * закреплено, какой факт к какой причине приводит и, что важнее, где мы
 * причину НЕ выдумываем.
 */
class AdesVerdictTest : FunSpec({

    val now = Date()
    val hour = 3_600_000L

    fun certificate(
        valid: Boolean = true,
        revocations: List<CertificateRevocationStatus>? = listOf(
            CertificateRevocationStatus(revoked = false, by = CertificateRevocation.OCSP, result = RevocationResult.ACTIVE),
        ),
        notBefore: Date = Date(now.time - 30 * 24 * hour),
        notAfter: Date = Date(now.time + 30 * 24 * hour),
    ) = CertificateInfo(valid = valid, revocations = revocations, notBefore = notBefore, notAfter = notAfter)

    test("everything checks out: VALID without a reason") {
        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(certificate()),
            bindingMatches = true,
            claimedLevel = AdesLevel.T,
            at = now,
            revocationRequested = true,
        )

        verdict.status shouldBe AdesValidationStatus.VALID
        verdict.subIndication.shouldBeNull()
    }

    test("no signer certificate: nothing to check") {
        val verdict = AdesVerdict.of(
            signatureValid = false,
            certificates = emptyList(),
            bindingMatches = true,
            claimedLevel = AdesLevel.B,
            at = now,
            revocationRequested = false,
        )

        verdict.status shouldBe AdesValidationStatus.INVALID
        verdict.subIndication shouldBe AdesSubIndication.NO_SIGNING_CERTIFICATE_FOUND
    }

    test("broken signature over a healthy certificate is a crypto failure") {
        val verdict = AdesVerdict.of(
            signatureValid = false,
            certificates = listOf(certificate()),
            bindingMatches = true,
            claimedLevel = AdesLevel.B,
            at = now,
            revocationRequested = false,
        )

        verdict.status shouldBe AdesValidationStatus.INVALID
        verdict.subIndication shouldBe AdesSubIndication.SIG_CRYPTO_FAILURE
    }

    test("a signature bound to another certificate is reported as such") {
        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(certificate()),
            bindingMatches = false,
            claimedLevel = AdesLevel.B,
            at = now,
            revocationRequested = false,
        )

        verdict.status shouldBe AdesValidationStatus.INVALID
        verdict.subIndication shouldBe AdesSubIndication.CERT_HASH_MISMATCH
    }

    test("revocation with a proven signing time is a revoked certificate") {
        val revoked = certificate(
            valid = false,
            revocations = listOf(
                CertificateRevocationStatus(
                    revoked = true, by = CertificateRevocation.OCSP,
                    revocationTime = Date(now.time - hour), result = RevocationResult.REVOKED,
                ),
            ),
        )

        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(revoked),
            bindingMatches = true,
            claimedLevel = AdesLevel.T,
            at = now,
            revocationRequested = true,
            timestampVerified = true,
        )

        verdict.status shouldBe AdesValidationStatus.INVALID
        verdict.subIndication shouldBe AdesSubIndication.CERT_REVOKED
    }

    test("the same revocation without a proven time is indeterminate, not invalid") {
        // Без метки времени доказать, что подпись поставлена до отзыва, нечем —
        // но и утверждать обратное мы не вправе.
        val revoked = certificate(
            valid = false,
            revocations = listOf(
                CertificateRevocationStatus(
                    revoked = true, by = CertificateRevocation.OCSP,
                    revocationTime = Date(now.time - hour), result = RevocationResult.REVOKED,
                ),
            ),
        )

        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(revoked),
            bindingMatches = true,
            claimedLevel = AdesLevel.B,
            at = now,
            revocationRequested = true,
        )

        verdict.status shouldBe AdesValidationStatus.INDETERMINATE
        verdict.subIndication shouldBe AdesSubIndication.REVOKED_NO_POE
    }

    test("unreachable revocation data is indeterminate") {
        val unchecked = certificate(
            valid = false,
            revocations = listOf(
                CertificateRevocationStatus(revoked = false, by = CertificateRevocation.OCSP, result = RevocationResult.UNAVAILABLE),
            ),
        )

        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(unchecked),
            bindingMatches = true,
            claimedLevel = AdesLevel.B,
            at = now,
            revocationRequested = true,
        )

        verdict.status shouldBe AdesValidationStatus.INDETERMINATE
        verdict.subIndication shouldBe AdesSubIndication.REVOCATION_DATA_MISSING
    }

    test("a certificate that had expired by the checked moment") {
        val expired = certificate(
            valid = false,
            notBefore = Date(now.time - 40 * 24 * hour),
            notAfter = Date(now.time - 24 * hour),
        )

        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(expired),
            bindingMatches = true,
            claimedLevel = AdesLevel.B,
            at = now,
            revocationRequested = false,
        )

        verdict.status shouldBe AdesValidationStatus.INDETERMINATE
        verdict.subIndication shouldBe AdesSubIndication.OUT_OF_BOUNDS_NO_POE
    }

    test("a timestamp that does not verify leaves the signature indeterminate") {
        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(certificate()),
            bindingMatches = true,
            claimedLevel = AdesLevel.T,
            at = now,
            revocationRequested = false,
            timestampVerified = false,
        )

        verdict.status shouldBe AdesValidationStatus.INDETERMINATE
        verdict.subIndication shouldBe AdesSubIndication.TIMESTAMP_INVALID
    }

    test("an unconfirmed LT level without a revocation check is not a complaint") {
        // Отзыв не запрашивали — вшитый материал никто и не смотрел. Это
        // видно по verifiedLevel и поводом для INDETERMINATE не является.
        val verdict = AdesVerdict.of(
            signatureValid = true,
            certificates = listOf(certificate()),
            bindingMatches = true,
            claimedLevel = AdesLevel.LT,
            at = now,
            revocationRequested = false,
            embeddedUsed = false,
        )

        verdict.status shouldBe AdesValidationStatus.VALID
    }

    test("the document takes the worst verdict of its signatures") {
        val verdicts = listOf(
            AdesVerdict.Verdict(AdesValidationStatus.VALID),
            AdesVerdict.Verdict(AdesValidationStatus.INDETERMINATE, AdesSubIndication.REVOCATION_DATA_MISSING),
            AdesVerdict.Verdict(AdesValidationStatus.INVALID, AdesSubIndication.SIG_CRYPTO_FAILURE),
        )

        AdesVerdict.worst(verdicts) shouldBe verdicts[2]
        AdesVerdict.worst(verdicts.take(2)) shouldBe verdicts[1]
        AdesVerdict.worst(emptyList()).shouldBeNull()
    }
})
