package kz.ncanode.dto

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import java.util.Date

/**
 * Темпоральная семантика отзыва (CAdES-T): подпись с доказанным временем
 * [signingTime] переживает отзыв сертификата только если отзыв случился
 * строго позже подписи и по benign-причине. Покрывает [OcspStatus.isValidAt],
 * [CrlStatus.isValidAt] и стоящую за ними `RevocationPolicy`.
 *
 * Реальный кейс из прода: подписант поставил подпись в 05:48:41, а в 05:53:13
 * перевыпустил ключ → старый отозван с reason=SUPERSEDED. Подпись должна
 * остаться валидной.
 */
class RevocationTemporalTest : FunSpec({

    val signingTime = Date(1_000_000L)
    val revokedAfter = Date(2_000_000L)   // отозван ПОСЛЕ подписи
    val revokedBefore = Date(500_000L)    // отозван ДО подписи

    // RFC 5280 §5.3.1 reason codes (== ordinal CRLReason)
    val unspecified = 0
    val keyCompromise = 1
    val caCompromise = 2
    val affiliationChanged = 3
    val superseded = 4
    val cessationOfOperation = 5
    val certificateHold = 6
    val privilegeWithdrawn = 9
    val aaCompromise = 10

    fun ocsp(reason: Int, at: Date?) =
        OcspStatus(result = OcspResult.REVOKED, revocationTime = at, revocationReason = reason)

    fun crl(reason: String?, at: Date?) =
        CrlStatus(result = CrlResult.REVOKED, revocationDate = at, reason = reason)

    // --- OCSP ------------------------------------------------------------

    test("OCSP ACTIVE is valid at any time") {
        OcspStatus(result = OcspResult.ACTIVE).isValidAt(signingTime) shouldBe true
    }

    test("OCSP UNKNOWN is never valid") {
        OcspStatus(result = OcspResult.UNKNOWN).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED superseded AFTER signing -> valid (the прод case)") {
        ocsp(superseded, revokedAfter).isValidAt(signingTime) shouldBe true
    }

    test("OCSP REVOKED superseded BEFORE signing -> invalid") {
        ocsp(superseded, revokedBefore).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED superseded EXACTLY at signing -> invalid (not strictly after)") {
        ocsp(superseded, signingTime).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED keyCompromise after signing -> invalid (retroactive)") {
        ocsp(keyCompromise, revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED caCompromise / aaCompromise after signing -> invalid") {
        ocsp(caCompromise, revokedAfter).isValidAt(signingTime) shouldBe false
        ocsp(aaCompromise, revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED unspecified after signing -> invalid (conservative)") {
        ocsp(unspecified, revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED certificateHold after signing -> invalid (conservative)") {
        ocsp(certificateHold, revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED other benign reasons after signing -> valid") {
        ocsp(affiliationChanged, revokedAfter).isValidAt(signingTime) shouldBe true
        ocsp(cessationOfOperation, revokedAfter).isValidAt(signingTime) shouldBe true
        ocsp(privilegeWithdrawn, revokedAfter).isValidAt(signingTime) shouldBe true
    }

    test("OCSP REVOKED with missing revocationTime -> invalid") {
        ocsp(superseded, null).isValidAt(signingTime) shouldBe false
    }

    test("OCSP REVOKED with absent reason code (-1) after signing -> invalid") {
        ocsp(-1, revokedAfter).isValidAt(signingTime) shouldBe false
    }

    // --- CRL -------------------------------------------------------------

    test("CRL ACTIVE is valid at any time") {
        CrlStatus(result = CrlResult.ACTIVE).isValidAt(signingTime) shouldBe true
    }

    test("CRL REVOKED SUPERSEDED after signing -> valid") {
        crl("SUPERSEDED", revokedAfter).isValidAt(signingTime) shouldBe true
    }

    test("CRL REVOKED SUPERSEDED before signing -> invalid") {
        crl("SUPERSEDED", revokedBefore).isValidAt(signingTime) shouldBe false
    }

    test("CRL REVOKED KEY_COMPROMISE after signing -> invalid") {
        crl("KEY_COMPROMISE", revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("CRL REVOKED UNSPECIFIED / CERTIFICATE_HOLD after signing -> invalid") {
        crl("UNSPECIFIED", revokedAfter).isValidAt(signingTime) shouldBe false
        crl("CERTIFICATE_HOLD", revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("CRL REVOKED with blank/unknown reason after signing -> invalid") {
        crl("", revokedAfter).isValidAt(signingTime) shouldBe false
        crl(null, revokedAfter).isValidAt(signingTime) shouldBe false
        crl("NOT_A_REAL_REASON", revokedAfter).isValidAt(signingTime) shouldBe false
    }

    test("CRL REVOKED with missing revocationDate -> invalid") {
        crl("SUPERSEDED", null).isValidAt(signingTime) shouldBe false
    }
})
