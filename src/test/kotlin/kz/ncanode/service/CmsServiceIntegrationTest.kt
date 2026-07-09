package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.ncanode.TestResources
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.CmsCreateBatchRequest
import kz.ncanode.dto.request.CmsCreateRequest
import kz.ncanode.dto.request.CmsExtractBatchRequest
import kz.ncanode.dto.request.CmsVerifyBatchRequest
import kz.ncanode.dto.certificate.RevocationResult
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.util.Base64

/**
 * End-to-end тест полного CMS-pipeline'а: sign -> verify против реальной
 * тестовой инфраструктуры НИТ (test.pki.gov.kz). Покрывает интеграцию
 * KalkanWrapper + CmsService + TspService + OcspService + CrlService +
 * CertificateService + CaService в одном проходе.
 *
 * Требует сетевого доступа к test.pki.gov.kz (CA bundle download +
 * OCSP/TSP responses). Конфигурация — `application-test.yml`.
 */
@SpringBootTest
@ActiveProfiles("test")
class CmsServiceIntegrationTest(
    @param:Autowired private val cmsService: CmsService,
    @param:Autowired private val caService: CaService,
    @param:Autowired private val kalkanWrapper: KalkanWrapper,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec {
        // CaService.updateCache @Scheduled, но через TaskScheduler — асинхронно.
        // Принудительно догружаем CA-bundle перед тестами, иначе первый verify
        // с OCSP падает на отсутствии issuer'а.
        caService.updateCache(true)
    }

    fun signerOf(p12Name: String) = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/$p12Name")
        password = TestResources.P12_PASSWORD
    }

    fun b64(s: String): String = Base64.getEncoder().encodeToString(s.toByteArray())

    test("sign + verify roundtrip without TSP, no revocation check") {
        val request = CmsCreateRequest().apply {
            data = b64("hello world")
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val signed = cmsService.create(request)
        signed.cms.shouldNotBeNull()

        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
        // Без isWithTsp метка не ставится — tsp-поле должно отсутствовать.
        verification.signers[0].tsp.shouldBeNull()
    }

    test("sign + verify with TSP attaches signature-timestamp (CAdES-T)") {
        val request = CmsCreateRequest().apply {
            data = b64("CAdES-T payload")
            signers = listOf(signerOf("individual_valid.p12"))
            isWithTsp = true
        }
        val signed = cmsService.create(request)
        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
        // tsp-поле должно быть проставлено, genTime — Date'а с TSA.
        val signer = verification.signers[0]
        signer.tsp.shouldNotBeNull().genTime.shouldNotBeNull()
    }

    test("sign + verify with TSP and OCSP+CRL revocation checks stays valid") {
        // Production-сценарий: CMS с TSP-меткой верифицируется с включёнными
        // OCSP и CRL. Строгая CAdES-T проверка (TspService.verify) при этом
        // гоняет revocation-чеки и по TSA-сертификату — если TSA-цепочка
        // не резолвится (issuer вне CA bundle, OCSP UNKNOWN), весь CMS
        // ложно помечается invalid при полностью валидном подписанте.
        val request = CmsCreateRequest().apply {
            data = b64("CAdES-T + full revocation")
            signers = listOf(signerOf("individual_valid.p12"))
            isWithTsp = true
        }
        val signed = cmsService.create(request)
        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = true, checkCrl = true)
        verification.signers shouldHaveSize 1
        verification.signers[0].tsp.shouldNotBeNull()
        verification.valid shouldBe true
    }

    test("verify with OCSP returns invalid for revoked signer") {
        val request = CmsCreateRequest().apply {
            data = b64("data")
            signers = listOf(signerOf("individual_revoked.p12"))
        }
        val signed = cmsService.create(request)

        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = true, checkCrl = false)
        verification.valid shouldBe false
        // Контракт revocations[].result (quirk #28): отзыв виден явно per-channel,
        // а не только в top-level valid — иначе клиент не отличит «поймали отзыв»
        // от «OCSP упал». OCSP-канал должен показать REVOKED.
        val revocations = verification.signers.first().certificates.first().revocations.orEmpty()
        revocations.any { it.result == RevocationResult.REVOKED } shouldBe true
    }

    test("extract returns the original data from attached CMS") {
        val original = "extract me back"
        val request = CmsCreateRequest().apply {
            data = b64(original)
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val signed = cmsService.create(request)

        val extracted = cmsService.extract(signed.cms!!)
        val recovered = String(Base64.getDecoder().decode(extracted.data!!))
        recovered shouldBe original
    }

    test("detached CMS: verify with data argument") {
        val payload = "detached payload"
        val payloadB64 = b64(payload)
        val request = CmsCreateRequest().apply {
            data = payloadB64
            signers = listOf(signerOf("individual_valid.p12"))
            isDetached = true
        }
        val signed = cmsService.create(request)

        // Detached CMS не содержит signedContent — extract должен пожаловаться.
        val verification = cmsService.verify(signed.cms!!, payloadB64, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
    }

    test("verify: detached CMS with WRONG data is rejected (signature must be checked)") {
        // Крипто-негатив: без реальной проверки подписи это прошло бы как
        // valid=true. Подпись detached-CMS стоит над "correct", проверяем с
        // другими данными. Реализация отвергает несовпадение дайджеста — либо
        // valid=false, либо ClientException("content hash ... different").
        // Главное — вход НЕ принимается как valid=true.
        val signed = cmsService.create(CmsCreateRequest().apply {
            data = b64("correct payload")
            signers = listOf(signerOf("individual_valid.p12"))
            isDetached = true
        })
        val accepted = try {
            cmsService.verify(signed.cms!!, b64("tampered payload"), checkOcsp = false, checkCrl = false).valid
        } catch (e: ClientException) {
            false // дайджест не сошёлся → отвергнуто на этапе проверки подписи
        }
        accepted shouldBe false
    }

    test("multi-signer CMS: two valid signers both verified") {
        val request = CmsCreateRequest().apply {
            data = b64("multi-sign payload")
            signers = listOf(
                signerOf("individual_valid.p12"),
                signerOf("legal_ceo_valid.p12"),
            )
        }
        val signed = cmsService.create(request)
        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 2
        // У каждого signer'а есть свой сертификат.
        verification.signers.forEach { it.certificates shouldHaveSize 1 }
    }

    test("verify response carries status=200 and message=OK by default") {
        val request = CmsCreateRequest().apply {
            data = b64("anything")
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val signed = cmsService.create(request)
        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.status shouldBe 200
        verification.message shouldBe "OK"
    }

    test("expired cert + verify without TSP is invalid (cert outside validity window)") {
        // expired_individual.p12 — старого периода 2024-2025; на 2026 истёк.
        // Без TSP-метки validationDate = now, cert.isDateValid(now) = false.
        val request = CmsCreateRequest().apply {
            data = b64("expired signer test")
            signers = listOf(signerOf("expired_individual.p12"))
        }
        val signed = cmsService.create(request)
        val verification = cmsService.verify(signed.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe false
    }

    test("addSigners appends a second signer to existing CMS") {
        val firstSigned = cmsService.create(CmsCreateRequest().apply {
            data = b64("addSigners payload")
            signers = listOf(signerOf("individual_valid.p12"))
        })

        val second = cmsService.addSigners(CmsCreateRequest().apply {
            cms = firstSigned.cms
            signers = listOf(signerOf("legal_ceo_valid.p12"))
        })

        val verification = cmsService.verify(second.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 2
    }

    test("addSigners preserves TSP attribute on already-signed signers") {
        // 1) Первый раз — с TSP.
        val firstSigned = cmsService.create(CmsCreateRequest().apply {
            data = b64("preserve TSP test")
            signers = listOf(signerOf("individual_valid.p12"))
            isWithTsp = true
        })

        // 2) Добавляем второго с TSP — у первого TSP должен остаться, у нового — тоже.
        val second = cmsService.addSigners(CmsCreateRequest().apply {
            cms = firstSigned.cms
            signers = listOf(signerOf("legal_ceo_valid.p12"))
            isWithTsp = true
        })

        val verification = cmsService.verify(second.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 2
        verification.signers.forEach { it.tsp.shouldNotBeNull() }
    }

    test("addSigners requires non-empty cms argument") {
        val ex = try {
            cmsService.addSigners(CmsCreateRequest().apply {
                cms = null
                signers = listOf(signerOf("individual_valid.p12"))
            })
            null
        } catch (e: Exception) {
            e
        }
        ex.shouldNotBeNull()
        ex.message.shouldNotBeNull() shouldContain "CMS"
    }

    test("createBatch: all items signed, each independently verifiable") {
        val request = CmsCreateBatchRequest().apply {
            data = listOf(b64("payload-1"), b64("payload-2"), b64("payload-3"))
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val response = cmsService.createBatch(request)

        response.results shouldHaveSize 3
        response.results.forEach {
            it.status shouldBe 200
            it.cms.shouldNotBeNull()
        }
        // Каждый CMS должен независимо верифицироваться.
        response.results.forEach { item ->
            cmsService.verify(item.cms!!, null, checkOcsp = false, checkCrl = false).valid shouldBe true
        }
    }

    test("createBatch: TSP flag propagates to each item") {
        val request = CmsCreateBatchRequest().apply {
            data = listOf(b64("tsp-a"), b64("tsp-b"))
            signers = listOf(signerOf("individual_valid.p12"))
            isWithTsp = true
        }
        val response = cmsService.createBatch(request)

        response.results shouldHaveSize 2
        response.results.forEach { item ->
            val verification = cmsService.verify(item.cms!!, null, checkOcsp = false, checkCrl = false)
            verification.valid shouldBe true
            // У каждого signer'а должна стоять TSP-метка с genTime.
            verification.signers.shouldHaveSize(1).first().tsp.shouldNotBeNull().genTime.shouldNotBeNull()
        }
    }

    test("verifyBatch: each CMS verified independently with valid flag per item") {
        // Готовим два CMS через createBatch и проверяем их одним verifyBatch.
        val signed = cmsService.createBatch(CmsCreateBatchRequest().apply {
            data = listOf(b64("vb-a"), b64("vb-b"))
            signers = listOf(signerOf("individual_valid.p12"))
        })

        val verifyResp = cmsService.verifyBatch(CmsVerifyBatchRequest().apply {
            items = signed.results.map { item ->
                CmsVerifyBatchRequest.Item().apply { cms = item.cms!! }
            }
        })

        verifyResp.results shouldHaveSize 2
        verifyResp.results.forEach { it.valid shouldBe true }
    }

    test("verifyBatch: detached CMS — each item passes its own data") {
        val payload1 = "detached-batch-1"
        val payload2 = "detached-batch-2"

        val signed1 = cmsService.create(CmsCreateRequest().apply {
            data = b64(payload1)
            signers = listOf(signerOf("individual_valid.p12"))
            isDetached = true
        })
        val signed2 = cmsService.create(CmsCreateRequest().apply {
            data = b64(payload2)
            signers = listOf(signerOf("individual_valid.p12"))
            isDetached = true
        })

        val response = cmsService.verifyBatch(CmsVerifyBatchRequest().apply {
            items = listOf(
                CmsVerifyBatchRequest.Item().apply { cms = signed1.cms!!; data = b64(payload1) },
                CmsVerifyBatchRequest.Item().apply { cms = signed2.cms!!; data = b64(payload2) },
            )
        })

        response.results shouldHaveSize 2
        response.results.forEach { it.valid shouldBe true }
    }

    test("verifyBatch: OCSP flag propagates — revoked signer flagged as invalid") {
        val signedOk = cmsService.create(CmsCreateRequest().apply {
            data = b64("ok")
            signers = listOf(signerOf("individual_valid.p12"))
        })
        val signedRevoked = cmsService.create(CmsCreateRequest().apply {
            data = b64("revoked")
            signers = listOf(signerOf("individual_revoked.p12"))
        })

        val response = cmsService.verifyBatch(CmsVerifyBatchRequest().apply {
            items = listOf(
                CmsVerifyBatchRequest.Item().apply { cms = signedOk.cms!! },
                CmsVerifyBatchRequest.Item().apply { cms = signedRevoked.cms!! },
            )
            revocationCheck = setOf(CertificateRevocation.OCSP)
        })

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        response.results[1].valid shouldBe false
    }

    test("verifyBatch: partial response — bad CMS doesn't kill the rest") {
        val signed = cmsService.create(CmsCreateRequest().apply {
            data = b64("good-cms")
            signers = listOf(signerOf("individual_valid.p12"))
        })

        val response = cmsService.verifyBatch(CmsVerifyBatchRequest().apply {
            items = listOf(
                CmsVerifyBatchRequest.Item().apply { cms = signed.cms!! },
                CmsVerifyBatchRequest.Item().apply { cms = "###not-base64-cms###" },
            )
        })

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        // Невалидный CMS — verify() кидает ClientException(400) на парсинге.
        response.results[1].valid shouldBe false
        response.results[1].status shouldBe 400
    }

    test("extractBatch: roundtrip — sign + extract returns original payloads") {
        val payloads = listOf("alpha", "beta", "gamma")
        val signed = cmsService.createBatch(CmsCreateBatchRequest().apply {
            data = payloads.map { b64(it) }
            signers = listOf(signerOf("individual_valid.p12"))
        })

        val extracted = cmsService.extractBatch(CmsExtractBatchRequest().apply {
            cms = signed.results.map { it.cms!! }
        })

        extracted.results shouldHaveSize 3
        extracted.results.forEachIndexed { i, item ->
            item.status shouldBe 200
            String(java.util.Base64.getDecoder().decode(item.data!!)) shouldBe payloads[i]
        }
    }

    test("extractBatch: detached CMS item gets 400 ClientException, others succeed") {
        val signedAttached = cmsService.create(CmsCreateRequest().apply {
            data = b64("attached-payload")
            signers = listOf(signerOf("individual_valid.p12"))
        })
        val signedDetached = cmsService.create(CmsCreateRequest().apply {
            data = b64("detached-payload")
            signers = listOf(signerOf("individual_valid.p12"))
            isDetached = true
        })

        val response = cmsService.extractBatch(CmsExtractBatchRequest().apply {
            cms = listOf(signedAttached.cms!!, signedDetached.cms!!)
        })

        response.results shouldHaveSize 2
        response.results[0].status shouldBe 200
        response.results[0].data.shouldNotBeNull()
        // Detached CMS не имеет signedContent — extract бросает ClientException(400).
        response.results[1].status shouldBe 400
        response.results[1].data shouldBe null
    }

    test("createBatch: partial response — bad data in middle doesn't kill the rest") {
        // Второй элемент — не валидный base64. ServerException → 500, остальные ОК.
        val request = CmsCreateBatchRequest().apply {
            data = listOf(b64("ok-1"), "###not-base64###", b64("ok-3"))
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val response = cmsService.createBatch(request)

        response.results shouldHaveSize 3
        response.results[0].status shouldBe 200
        response.results[0].cms.shouldNotBeNull()
        response.results[1].status shouldBe 500
        response.results[1].cms shouldBe null
        response.results[2].status shouldBe 200
        response.results[2].cms.shouldNotBeNull()
    }

    test("addSigners on detached CMS requires data argument") {
        val firstSigned = cmsService.create(CmsCreateRequest().apply {
            data = b64("detached for re-sign")
            signers = listOf(signerOf("individual_valid.p12"))
            isDetached = true
        })

        val ex = try {
            cmsService.addSigners(CmsCreateRequest().apply {
                cms = firstSigned.cms
                // data НЕ передаём — для detached CMS это ошибка.
                signers = listOf(signerOf("legal_ceo_valid.p12"))
            })
            null
        } catch (e: Exception) {
            e
        }
        ex.shouldNotBeNull()
    }

    // --- Audit fix 1.1: CMS без подписантов не может считаться валидным ---
    // RFC 5652 §5.1: SignedData с пустым signerInfos ничего не удостоверяет.
    test("verify: CMS with zero SignerInfos is invalid (RFC 5652 §5.1)") {
        // Degenerate "certs-only"-style CMS: контент есть, подписантов нет.
        val signed = CMSSignedDataGenerator().generate(
            CMSProcessableByteArray("no signers here".toByteArray()),
            true,
            KalkanProvider.PROVIDER_NAME,
        )
        val b64 = Base64.getEncoder().encodeToString(signed.encoded)

        val result = cmsService.verify(b64, null, checkOcsp = false, checkCrl = false)
        result.valid shouldBe false
        result.signers.shouldBeEmpty()
    }

    // --- Audit fix 1.2: подписант без вложенного сертификата = провал ---
    // RFC 5652 §5.6: подпись обязана быть криптографически проверена; если
    // cert подписанта не вложен, проверять нечем — это не "успех".
    test("verify: CMS signer without embedded certificate is invalid (RFC 5652 §5.6)") {
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null,
            TestResources.P12_PASSWORD,
        )
        val x509 = ks.certificate.x509Certificate

        val generator = CMSSignedDataGenerator().apply {
            addSigner(ks.privateKey, x509, getDigestAlgorithmOidBYSignAlgorithmOid(x509.sigAlgOID))
            // НАМЕРЕННО не вызываем addCertificatesAndCRLs — cert подписанта
            // отсутствует в итоговом CMS, signer.verify() проверять будет нечем.
        }
        val signed = generator.generate(
            CMSProcessableByteArray("signed but cert stripped".toByteArray()),
            true,
            KalkanProvider.PROVIDER_NAME,
        )
        val b64 = Base64.getEncoder().encodeToString(signed.encoded)

        val result = cmsService.verify(b64, null, checkOcsp = false, checkCrl = false)
        result.valid shouldBe false
        // Подписант присутствует в отчёте, но без сертификатов.
        result.signers shouldHaveSize 1
        result.signers.first().certificates.shouldBeEmpty()
    }
})
