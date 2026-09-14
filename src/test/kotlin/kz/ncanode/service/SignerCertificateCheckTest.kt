package kz.ncanode.service

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kz.ncanode.configuration.OcspConfiguration
import kz.ncanode.configuration.SignConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.exception.ClientException
import kz.ncanode.wrapper.CertificateWrapper
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.util.Date

/**
 * Проверка сертификата подписанта перед подписанием — п. 4 Правил формирования
 * и проверки подлинности ЭЦП (приказ МИИ РК №500/НҚ).
 *
 * Режим выключен по умолчанию, поэтому здесь важны обе стороны: что выключенная
 * проверка не делает вообще ничего (в том числе не ходит в сеть на каждое
 * подписание) и что включённая отказывает клиенту на непригодном ключе.
 */
class SignerCertificateCheckTest : FunSpec({

    fun certificate(cn: String, notBefore: Date, notAfter: Date): CertificateWrapper {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val name = X500Name("CN=$cn")
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter, name, keyPair.public)
            .build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        return CertificateWrapper(JcaX509CertificateConverter().getCertificate(holder))
    }

    val hourAgo = Date(System.currentTimeMillis() - 3_600_000L)
    val yearAhead = Date(System.currentTimeMillis() + 365L * 86_400_000L)
    val yearAgo = Date(System.currentTimeMillis() - 365L * 86_400_000L)

    class Fixture(val service: CertificateService, val ocspService: OcspService, val crlService: CrlService)

    fun fixture(
        enabled: Boolean,
        ocsp: List<OcspStatus> = listOf(OcspStatus(result = OcspResult.ACTIVE)),
        crl: CrlStatus = CrlStatus(result = CrlResult.ACTIVE, fresh = true),
    ): Fixture {
        val ocspService = mockk<OcspService>().apply { every { verify(any(), any()) } returns ocsp }
        val crlService = mockk<CrlService>().apply { every { verify(any()) } returns crl }
        // Издателем самоподписанного сертификата выступает он сам — обход
        // цепочки на нём и остановится.
        val caService = mockk<CaService>().apply { every { getRootCertificateFor(any()) } answers { firstArg() } }
        val service = CertificateService(
            crlService = crlService,
            ocspService = ocspService,
            caService = caService,
            kalkanWrapper = mockk(relaxed = true),
            ocspConfiguration = OcspConfiguration(),
            signConfiguration = SignConfiguration().apply { isCertificateCheck = enabled },
        )
        return Fixture(service, ocspService, crlService)
    }

    test("disabled check touches neither the certificate nor the network") {
        // Дефолт. Просроченный ключ подписывает как раньше — поведение
        // существующих развёртываний не меняется, и лишнего OCSP-запроса на
        // каждое подписание не появляется.
        val expired = certificate("expired", yearAgo, hourAgo)
        val fx = fixture(enabled = false)

        shouldNotThrowAny { fx.service.ensureSignerCertificateUsable(expired) }
        verify(exactly = 0) { fx.ocspService.verify(any(), any()) }
        verify(exactly = 0) { fx.crlService.verify(any()) }
    }

    test("enabled check refuses an expired signer certificate") {
        // п. 4, подпункт 2: срок действия должен наступить и не истечь.
        val expired = certificate("expired", yearAgo, hourAgo)

        val error = shouldThrow<ClientException> {
            fixture(enabled = true).service.ensureSignerCertificateUsable(expired)
        }
        error.message!! shouldContain "cannot be used for signing"
    }

    test("enabled check refuses a revoked signer certificate") {
        // п. 4, подпункт 3: отзыв проверяется через OCSP. Причина отзыва —
        // компрометация, она не прощается ни на какой момент.
        val revoked = certificate("revoked", hourAgo, yearAhead)
        val fx = fixture(
            enabled = true,
            ocsp = listOf(
                OcspStatus(
                    result = OcspResult.REVOKED,
                    revocationTime = Date(System.currentTimeMillis() - 60_000L),
                    // RFC 5280 §5.3.1: keyCompromise = 1.
                    revocationReason = 1,
                ),
            ),
        )

        shouldThrow<ClientException> { fx.service.ensureSignerCertificateUsable(revoked) }
    }

    test("enabled check passes a usable signer certificate") {
        val usable = certificate("usable", hourAgo, yearAhead)
        val fx = fixture(enabled = true)

        shouldNotThrowAny { fx.service.ensureSignerCertificateUsable(usable) }
        verify(exactly = 1) { fx.ocspService.verify(any(), any()) }
    }
})
