package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kz.ncanode.TestResources
import kz.ncanode.dto.request.Pkcs12AliasesBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoBatchRequest
import kz.ncanode.dto.request.Pkcs12InfoRequest
import kz.ncanode.dto.request.SbaVerifyBatchRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.X509InfoBatchRequest
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.security.KeyStore
import java.util.Base64

/**
 * Покрывает не-CMS-инициированные эндпоинты CertificateService:
 * verifyCerts (pkcs12/info), info (x509/info), verify (x509/verify SBA).
 * Эти пути не задействуются CMS-тестами — отдельный suite даёт ощутимый
 * прирост покрытия CertificateService.
 */
@SpringBootTest
@ActiveProfiles("test")
class CertificateServiceIntegrationTest(
    @param:Autowired private val certificateService: CertificateService,
    @param:Autowired private val caService: CaService,
    @param:Autowired private val kalkanWrapper: KalkanWrapper,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec { caService.updateCache(true) }

    fun extractCertBase64(p12Name: String): String {
        val p12 = TestResources.loadBytes("p12/$p12Name")
        val ks = KeyStore.getInstance("PKCS12", kalkanWrapper.kalkanProvider)
        ks.load(p12.inputStream(), TestResources.P12_PASSWORD.toCharArray())
        val alias = ks.aliases().nextElement()
        return Base64.getEncoder().encodeToString(ks.getCertificate(alias).encoded)
    }

    test("verifyCerts() reads p12 + reports cert as valid") {
        val request = Pkcs12InfoRequest().apply {
            keys = listOf(SignerRequest().apply {
                key = TestResources.loadAsBase64("p12/individual_valid.p12")
                password = TestResources.P12_PASSWORD
            })
        }
        val response = certificateService.verifyCerts(request)
        response.valid shouldBe true
        response.signers shouldHaveSize 1
        response.signers[0].shouldNotBeNull().valid shouldBe true
    }

    test("info() parses multiple base64 certs and returns CertificateInfo per cert") {
        val certs = listOf(
            extractCertBase64("individual_valid.p12"),
            extractCertBase64("legal_ceo_valid.p12"),
        )
        val response = certificateService.info(certs, checkOcsp = false, checkCrl = false)
        response.valid shouldBe true
        response.signers shouldHaveSize 2
        response.signers.forEach { it.shouldNotBeNull() }
    }

    test("info() with empty list returns valid=false") {
        val response = certificateService.info(emptyList(), checkOcsp = false, checkCrl = false)
        response.valid shouldBe false
        response.signers shouldHaveSize 0
    }

    // Валидный base64 но не cert — graceful path (CertificateException ловится).
    val nonCertBase64 = Base64.getEncoder().encodeToString(byteArrayOf(0x01, 0x02, 0x03, 0x04))

    test("info() with one non-cert base64 entry marks it null and returns invalid") {
        val response = certificateService.info(
            listOf(nonCertBase64),
            checkOcsp = false, checkCrl = false,
        )
        response.valid shouldBe false
        // Структурный invariant: per-position null preserves signer ordering
        // (raised when caller looks up which cert in the array failed).
        response.signers shouldHaveSize 1
        response.signers[0].shouldBeNull()
        response.message.shouldNotBeNull() shouldContain "Invalid certificate"
    }

    test("info() with mixed valid + non-cert marks valid one OK, other as null") {
        val response = certificateService.info(
            listOf(extractCertBase64("individual_valid.p12"), nonCertBase64),
            checkOcsp = false, checkCrl = false,
        )
        response.valid shouldBe false
        response.signers shouldHaveSize 2
        response.signers[0].shouldNotBeNull()
        response.signers[1].shouldBeNull()
    }

    test("verify() with non-cert base64 returns invalid + null signer") {
        val response = certificateService.verify(
            certBase64 = nonCertBase64,
            signature = "AA==",
            data = "anything",
            checkOcsp = false,
            checkCrl = false,
        )
        response.valid shouldBe false
        response.signers shouldHaveSize 1
        response.signers[0].shouldBeNull()
    }

    test("verify() with valid cert but garbage signature returns valid=false") {
        val cert = extractCertBase64("individual_valid.p12")
        val response = certificateService.verify(
            certBase64 = cert,
            signature = Base64.getEncoder().encodeToString(ByteArray(64) { 0 }),
            data = "anything",
            checkOcsp = false,
            checkCrl = false,
        )
        response.valid shouldBe false
        // Cert сам по себе валидный + parsed → присутствует в signers.
        response.signers shouldHaveSize 1
        response.signers[0].shouldNotBeNull()
    }

    test("infoBatch: per-cert results — valid+invalid coexist, each with own status") {
        val response = certificateService.infoBatch(X509InfoBatchRequest().apply {
            certs = listOf(
                extractCertBase64("individual_valid.p12"),
                nonCertBase64,
                extractCertBase64("legal_ceo_valid.p12"),
            )
        })

        response.results shouldHaveSize 3
        response.results[0].status shouldBe 200
        response.results[0].signer.shouldNotBeNull()
        // Невалидный base64-cert → status=400 per-item, signer=null.
        response.results[1].status shouldBe 400
        response.results[1].signer.shouldBeNull()
        response.results[2].status shouldBe 200
        response.results[2].signer.shouldNotBeNull()
    }

    test("infoBatch: revoked cert is parsed (status=200) but signer.valid=false with OCSP") {
        val response = certificateService.infoBatch(X509InfoBatchRequest().apply {
            certs = listOf(extractCertBase64("individual_revoked.p12"))
            revocationCheck = setOf(kz.ncanode.dto.certificate.CertificateRevocation.OCSP)
        })

        response.results shouldHaveSize 1
        // Парсинг успешен → status 200, но revocation на бизнес-уровне → signer.valid=false.
        response.results[0].status shouldBe 200
        val signer = response.results[0].signer.shouldNotBeNull()
        signer.valid shouldBe false
    }

    test("verifyBatch (SBA): mixed items — valid cert + non-cert give per-item results") {
        val validCert = extractCertBase64("individual_valid.p12")

        val response = certificateService.verifyBatch(SbaVerifyBatchRequest().apply {
            items = listOf(
                // Валидный cert + garbage signature → valid=false, signer заполнен.
                SbaVerifyBatchRequest.Item().apply {
                    certificate = validCert
                    signature = Base64.getEncoder().encodeToString(ByteArray(64) { 0 })
                    data = "anything"
                },
                // Не-cert → valid=false, signer=null.
                SbaVerifyBatchRequest.Item().apply {
                    certificate = nonCertBase64
                    signature = "AA=="
                    data = "x"
                },
            )
        })

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe false
        response.results[0].signers shouldHaveSize 1
        response.results[0].signers[0].shouldNotBeNull()
        response.results[1].valid shouldBe false
        response.results[1].signers shouldHaveSize 1
        response.results[1].signers[0].shouldBeNull()
    }

    test("verifyCertsBatch: per-key status — bad password / good key coexist") {
        val response = certificateService.verifyCertsBatch(Pkcs12InfoBatchRequest().apply {
            keys = listOf(
                SignerRequest().apply {
                    key = TestResources.loadAsBase64("p12/individual_valid.p12")
                    password = TestResources.P12_PASSWORD
                },
                SignerRequest().apply {
                    key = TestResources.loadAsBase64("p12/individual_valid.p12")
                    password = "wrong-password"
                },
            )
        })

        response.results shouldHaveSize 2
        response.results[0].status shouldBe 200
        response.results[0].signer.shouldNotBeNull()
        // Неверный пароль p12 — ошибка входа клиента → KalkanWrapper.tryReadKey
        // бросает ClientException (400), batch-обвязка пишет per-item status=400
        // (аудит M1 / CLAUDE.md quirk #22 «400 — плохой p12 пароль»).
        response.results[1].status shouldBe 400
        response.results[1].signer.shouldBeNull()
    }

    test("aliasesBatch: per-key — valid p12 returns aliases, bad password returns 400") {
        val response = certificateService.aliasesBatch(Pkcs12AliasesBatchRequest().apply {
            keys = listOf(
                SignerRequest().apply {
                    key = TestResources.loadAsBase64("p12/individual_valid.p12")
                    password = TestResources.P12_PASSWORD
                },
                SignerRequest().apply {
                    key = TestResources.loadAsBase64("p12/individual_valid.p12")
                    password = "wrong"
                },
            )
        })

        response.results shouldHaveSize 2
        response.results[0].status shouldBe 200
        response.results[0].aliases.shouldNotBeNull()
        (response.results[0].aliases.size >= 1) shouldBe true
        // KeyException на неверном пароле → per-item 400, aliases пуст.
        response.results[1].status shouldBe 400
        response.results[1].aliases shouldBe emptyList()
    }

    test("attachValidationData is idempotent: second call doesn't re-fetch OCSP") {
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null,
            TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate

        certificateService.attachValidationData(cert, checkOcsp = true, checkCrl = false)
        val firstOcsp = cert.ocspStatus
        firstOcsp shouldNotBe null

        // Второй вызов: OCSP-результат не должен переписаться, идемпотентность.
        certificateService.attachValidationData(cert, checkOcsp = true, checkCrl = false)
        cert.ocspStatus shouldBe firstOcsp  // referential equality — не пересчитан
    }
})
