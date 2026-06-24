package kz.ncanode.dto

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kz.ncanode.dto.certificate.CertificateKeyUsage

/**
 * Audit fix 3.2: `getKeyUsage()` возвращает `null`, когда расширение keyUsage
 * отсутствует (RFC 5280 §4.2.1.3 — OPTIONAL). Раньше это валило валидный
 * сертификат NPE.
 */
class CertificateKeyUsageTest : FunSpec({

    test("null keyUsage (extension absent) → UNKNOWN, not NPE") {
        CertificateKeyUsage.fromKeyUsageBits(null) shouldBe CertificateKeyUsage.UNKNOWN
    }

    test("too-short bit array → UNKNOWN (no IndexOutOfBounds)") {
        CertificateKeyUsage.fromKeyUsageBits(booleanArrayOf(true)) shouldBe CertificateKeyUsage.UNKNOWN
    }

    test("digitalSignature + nonRepudiation → SIGN") {
        val bits = booleanArrayOf(true, true, false, false, false, false, false, false, false)
        CertificateKeyUsage.fromKeyUsageBits(bits) shouldBe CertificateKeyUsage.SIGN
    }

    test("digitalSignature + keyEncipherment → AUTH") {
        val bits = booleanArrayOf(true, false, true, false, false, false, false, false, false)
        CertificateKeyUsage.fromKeyUsageBits(bits) shouldBe CertificateKeyUsage.AUTH
    }
})
