package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.ASN1Set
import kz.gov.pki.kalkan.asn1.DEROctetString
import kz.gov.pki.kalkan.asn1.ASN1Sequence
import kz.gov.pki.kalkan.asn1.ASN1TaggedObject
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector
import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.cms.AttributeTable
import kz.gov.pki.kalkan.asn1.cms.ContentInfo
import kz.gov.pki.kalkan.asn1.cms.SignedData
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.ncanode.TestResources
import kz.ncanode.ades.CmsValidationData
import kz.ncanode.ades.CadesAttributes
import kz.ncanode.ades.CadesInspector
import kz.ncanode.ades.CmsArchiveTimestamp
import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.CadesSignBatchRequest
import kz.ncanode.dto.request.CadesSignRequest
import kz.ncanode.dto.request.CadesVerifyBatchRequest
import kz.ncanode.dto.request.CadesVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.util.getTspHashAlgorithmByOid
import java.security.MessageDigest
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.util.Base64

/**
 * CAdES по ETSI EN 319 122-1: уровни B и T.
 *
 * Состав атрибутов сверяется не с вольным прочтением стандарта, а с тем, что
 * кладёт официальная реализация НУЦ (NCALayer
 * из NCALayer) — цель этого сервиса именно совместимость с ней. Значения
 * проверяются точно: SHA-256 хэш сертификата даже для GOST-ключа, отсутствие
 * `IssuerSerial`, структура `cmsAlgorithmProtection`.
 *
 * Уровень T требует живого TSP (test.pki.gov.kz), как и остальные
 * интеграционные тесты проекта.
 */
@SpringBootTest
@ActiveProfiles("test")
class CadesServiceIntegrationTest(
    @param:Autowired private val cadesService: CadesService,
    @param:Autowired private val cmsService: CmsService,
    @param:Autowired private val tspService: TspService,
) : FunSpec({

    val kalkanWrapper = KalkanWrapper(KalkanProvider())
    val payload = Base64.getEncoder().encodeToString("CAdES compatibility payload".toByteArray())

    val provider = kalkanWrapper.kalkanProvider

    /** Встречается ли [needle] внутри [haystack] — как подстрока в строке. */
    fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { start ->
            needle.indices.all { haystack[start + it] == needle[it] }
        }

    fun signer(): SignerRequest = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/individual_valid.p12")
        password = TestResources.P12_PASSWORD
    }

    fun request(level: AdesLevel = AdesLevel.B, detached: Boolean = false): CadesSignRequest =
        CadesSignRequest().apply {
            data = payload
            signers = listOf(signer())
            this.level = level
            isDetached = detached
        }

    fun firstSigner(cms: String): SignerInformation =
        (CMSSignedData(Base64.getDecoder().decode(cms)).signerInfos.signers.first() as SignerInformation)

    val signerCertificate = kalkanWrapper.read(
        TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
    ).certificate.x509Certificate

    test("level B produces the signed attribute set NCALayer expects") {
        val response = cadesService.sign(request())
        response.level shouldBe AdesLevel.B
        val signed = firstSigner(response.cms!!).signedAttributes.shouldNotBeNull()

        // Обязательные для CMS — их добавляет генератор, а не мы; проверяем,
        // что передача собственной AttributeTable их не вытеснила.
        signed.get(CMSAttributes.contentType).shouldNotBeNull()
        signed.get(CMSAttributes.messageDigest).shouldNotBeNull()
        // Собственно AdES-B.
        signed.get(CMSAttributes.signingTime).shouldNotBeNull()
        signed.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2).shouldNotBeNull()
        signed.get(DERObjectIdentifier(CadesAttributes.CMS_ALGORITHM_PROTECTION_OID)).shouldNotBeNull()
    }

    test("signingCertificateV2 carries the SHA-256 certificate hash and no IssuerSerial") {
        val response = cadesService.sign(request())
        val attribute = firstSigner(response.cms!!).signedAttributes
            .get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
        val signingCertificate = SigningCertificateV2.getInstance(attribute.attrValues.getObjectAt(0))

        signingCertificate.certs.size shouldBe 1
        val certificateId = signingCertificate.certs[0]

        // SHA-256 даже для GOST-сертификата — так делает НУЦ.
        val expected = MessageDigest.getInstance("SHA-256").digest(signerCertificate.encoded)
        certificateId.certHash.contentEquals(expected) shouldBe true
        // hashAlgorithm не сериализуется: по RFC 5035 отсутствие = SHA-256.
        certificateId.issuerSerial.shouldBeNull()
    }

    test("cmsAlgorithmProtection pins the digest and the signature algorithm") {
        val response = cadesService.sign(request())
        val attribute = firstSigner(response.cms!!).signedAttributes
            .get(DERObjectIdentifier(CadesAttributes.CMS_ALGORITHM_PROTECTION_OID))
        val protection = ASN1Sequence.getInstance(attribute.attrValues.getObjectAt(0))

        val digest = AlgorithmIdentifier.getInstance(protection.getObjectAt(0))
        digest.objectId.id shouldBe getDigestAlgorithmOidBYSignAlgorithmOid(signerCertificate.sigAlgOID)

        // Алгоритм подписи идёт с implicit-тегом [1] (RFC 6211 §2).
        val tagged = protection.getObjectAt(1) as ASN1TaggedObject
        tagged.tagNo shouldBe 1
        AlgorithmIdentifier.getInstance(tagged, false).objectId.id shouldBe signerCertificate.sigAlgOID
    }

    test("level B signature verifies cryptographically over its own attributes") {
        val response = cadesService.sign(request())
        val signer = firstSigner(response.cms!!)
        // Подпись считается по signedAttrs — если бы наши атрибуты не попали
        // в подписанный набор, проверка бы не сошлась.
        signer.verify(signerCertificate, KalkanProvider.PROVIDER_NAME) shouldBe true
    }

    test("level B signature is accepted by the existing CMS verification pipeline") {
        // Добавление AdES-атрибутов не должно ломать наш собственный verify:
        // он их не требует и не обязан о них знать.
        val response = cadesService.sign(request())
        val verification = cmsService.verify(response.cms!!, null, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
    }

    test("level T attaches a signature timestamp the strict CAdES-T check accepts") {
        val response = cadesService.sign(request(level = AdesLevel.T))
        response.level shouldBe AdesLevel.T
        val signer = firstSigner(response.cms!!)

        val unsigned = signer.unsignedAttributes.shouldNotBeNull()
        val timestamp = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).shouldNotBeNull()

        // Не ограничиваемся «атрибут присутствует»: прогоняем метку через
        // собственную строгую проверку CAdES-T. Она сверяет imprint именно со
        // значением подписи внешнего подписанта и цепочку TSA на genTime, так
        // что на подложенном мусоре тест бы упал.
        val token = CMSSignedData(timestamp.attrValues.getObjectAt(0).getDERObject().getDEREncoded())
        val info = tspService.verify(token, signer.signature, false, false).shouldNotBeNull()
        info.genTime.shouldNotBeNull()

        // Атрибуты уровня B никуда не делись — T надстраивается, а не заменяет.
        signer.signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2).shouldNotBeNull()
    }

    test("detached signature carries no encapsulated content") {
        val response = cadesService.sign(request(detached = true))
        CMSSignedData(Base64.getDecoder().decode(response.cms!!)).signedContent.shouldBeNull()
    }

    test("verify reports level B and validates a B signature") {
        val signed = cadesService.sign(request())
        val result = cadesService.verify(CadesVerifyRequest().apply { cms = signed.cms!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.B
        result.verifiedLevel shouldBe AdesLevel.B
        result.signers.single().level shouldBe AdesLevel.B
    }

    test("verify reports level T for a timestamped signature") {
        val signed = cadesService.sign(request(level = AdesLevel.T))
        val result = cadesService.verify(CadesVerifyRequest().apply { cms = signed.cms!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.T
        result.verifiedLevel shouldBe AdesLevel.T
        result.signers.single().tsp.shouldNotBeNull()
    }

    test("verify reports the detached signature level when the data is supplied") {
        val signed = cadesService.sign(request(detached = true))
        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = signed.cms!!
                data = payload
            },
        )

        result.valid shouldBe true
        result.level shouldBe AdesLevel.B
    }

    test("verify rejects a signature bound to another certificate") {
        // Подпись настоящая и цепочка в порядке — расходится только привязка
        // signingCertificateV2. Без сверки атрибута такая подпись прошла бы
        // как валидная, поэтому проверяем именно через сервис: важно, что он
        // действительно смотрит на результат разбора, а не только на CmsService.
        val foreign = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/legal_ceo_valid.p12"), null, TestResources.P12_PASSWORD,
        ).certificate.x509Certificate
        val signerKeyStore = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val digestOid = getDigestAlgorithmOidBYSignAlgorithmOid(signerCertificate.sigAlgOID)

        val generator = CMSSignedDataGenerator()
        generator.addSigner(
            signerKeyStore.privateKey,
            signerCertificate,
            digestOid,
            CadesAttributes.signedAttributes(foreign, digestOid, KalkanProvider()),
            null as AttributeTable?,
        )
        generator.addCertificatesAndCRLs(
            CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(listOf(signerCertificate)),
                KalkanProvider.PROVIDER_NAME,
            ),
        )
        val tampered = generator.generate(
            CMSProcessableByteArray("payload".toByteArray()),
            true,
            KalkanProvider.PROVIDER_NAME,
        )

        val result = cadesService.verify(
            CadesVerifyRequest().apply { cms = Base64.getEncoder().encodeToString(tampered.encoded) },
        )
        result.valid shouldBe false
    }

    test("level LT embeds the certificate chain and revocation data") {
        val response = cadesService.sign(request(level = AdesLevel.LT))
        response.level shouldBe AdesLevel.LT

        val cms = CMSSignedData(Base64.getDecoder().decode(response.cms!!))
        // Цепочка: подписант плюс как минимум его издатель — без неё проверка
        // без сети невозможна.
        val certificates = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            .getCertificates(null)
        (certificates.size >= 2) shouldBe true

        // Данные об отзыве лежат в SignedData.crls (там же и OCSP-ответы,
        // завёрнутые в OtherRevocationInfoFormat) — так это делает NCALayer.
        CadesInspector.inspect(Base64.getDecoder().decode(response.cms!!), KalkanProvider())
            .single().level shouldBe AdesLevel.LT
    }

    test("level LT keeps the signature and its timestamp intact") {
        // Встраивание данных не должно ломать ни подпись, ни метку: материал
        // кладётся в неподписанные части SignedData.
        val response = cadesService.sign(request(level = AdesLevel.LT))
        val result = cadesService.verify(CadesVerifyRequest().apply { cms = response.cms!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.LT
        // Отзыв не запрашивали — вшитый материал не смотрели, значит уровень
        // подтверждён только до T. Объявить LT было бы неправдой.
        result.verifiedLevel shouldBe AdesLevel.T
        result.signers.single().tsp.shouldNotBeNull()
    }

    test("level LT is confirmed from the embedded material, not from the network") {
        // Тот же документ, но проверка отзыва запрошена. Вердикт приходит из
        // вшитых данных: verifiedLevel поднимается до LT только если они
        // оказались авторитетными на момент подписи.
        val response = cadesService.sign(request(level = AdesLevel.LT))
        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = response.cms!!
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LT
    }

    test("level LTA is confirmed only when the archive timestamp checks out") {
        val response = cadesService.sign(request(level = AdesLevel.LTA))
        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = response.cms!!
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        // Архивная метка пересчитана и проверена строгой TSP-проверкой.
        result.verifiedLevel shouldBe AdesLevel.LTA
    }

    test("level LTA attaches an archive timestamp of the modern profile") {
        val response = cadesService.sign(request(level = AdesLevel.LTA))
        response.level shouldBe AdesLevel.LTA

        val signer = firstSigner(response.cms!!)
        val archive = signer.unsignedAttributes.shouldNotBeNull()
            .get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3).shouldNotBeNull()

        // Индекс живёт внутри самой метки, а не рядом с ней.
        val token = TimeStampToken(CMSSignedData(archive.attrValues.getObjectAt(0).getDERObject().getDEREncoded()))
        val tokenSigner = CMSSignedData(token.encoded).signerInfos.signers.first() as SignerInformation
        tokenSigner.unsignedAttributes.shouldNotBeNull()
            .get(DERObjectIdentifier("0.4.0.19122.1.5")).shouldNotBeNull()

        CadesInspector.inspect(Base64.getDecoder().decode(response.cms!!), KalkanProvider())
            .single().level shouldBe AdesLevel.LTA
    }

    test("the archive timestamp imprint really covers the signature it is attached to") {
        // Самая содержательная проверка LTA: пересчитываем то, по чему должна
        // была считаться метка, и сверяем с imprint'ом внутри токена. Ошибка в
        // сериализации SignerInfo или в наборе полей всплывёт именно здесь —
        // структурные проверки её бы не заметили.
        val response = cadesService.sign(request(level = AdesLevel.LTA))
        val cms = CMSSignedData(Base64.getDecoder().decode(response.cms!!))
        val signer = cms.signerInfos.signers.first() as SignerInformation
        val provider = KalkanProvider()

        val archive = signer.unsignedAttributes.get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3)
        val token = TimeStampToken(CMSSignedData(archive.attrValues.getObjectAt(0).getDERObject().getDEREncoded()))
        val hashIndex = (CMSSignedData(token.encoded).signerInfos.signers.first() as SignerInformation)
            .unsignedAttributes.get(DERObjectIdentifier("0.4.0.19122.1.5"))

        val digestOid = getTspHashAlgorithmByOid(signerCertificate.sigAlgOID)
        val recomputed = MessageDigest.getInstance(digestOid, provider).digest(
            CmsArchiveTimestamp.imprintInput(
            cms, signer, digestOid, hashIndex, provider, Base64.getDecoder().decode(payload),
        ),
        )
        recomputed.contentEquals(token.timeStampInfo.messageImprintDigest) shouldBe true
    }

    test("the embedded hash index reproduces the state the timestamp was taken over") {
        // Индекс перечисляет хэши сертификатов, записей об отзыве и значений
        // неподписанных атрибутов НА МОМЕНТ проставления метки. Снимаем саму
        // метку и пересчитываем — должно совпасть побайтово.
        val response = cadesService.sign(request(level = AdesLevel.LTA))
        val cms = CMSSignedData(Base64.getDecoder().decode(response.cms!!))
        val signer = cms.signerInfos.signers.first() as SignerInformation
        val provider = KalkanProvider()

        val archive = signer.unsignedAttributes.get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3)
        val token = TimeStampToken(CMSSignedData(archive.attrValues.getObjectAt(0).getDERObject().getDEREncoded()))
        val embedded = (CMSSignedData(token.encoded).signerInfos.signers.first() as SignerInformation)
            .unsignedAttributes.get(DERObjectIdentifier("0.4.0.19122.1.5"))

        // Подписант без архивной метки — состояние, в котором индекс считался.
        val without = ASN1EncodableVector()
        val attributes = signer.unsignedAttributes.toASN1EncodableVector()
        for (index in 0 until attributes.size()) {
            val attribute = Attribute.getInstance(attributes.get(index))
            if (attribute.attrType != CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3) without.add(attribute)
        }
        val before = SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(without))

        val digestOid = getTspHashAlgorithmByOid(signerCertificate.sigAlgOID)
        val recomputed = CmsArchiveTimestamp.hashIndex(cms, before, digestOid, provider)

        recomputed.getDEREncoded().contentEquals(embedded.getDEREncoded()) shouldBe true
    }

    // ---- batch ----

    test("signBatch signs every item with the shared signer and level") {
        val second = Base64.getEncoder().encodeToString("second payload".toByteArray())
        val response = cadesService.signBatch(
            CadesSignBatchRequest().apply {
                data = listOf(payload, second)
                signers = listOf(signer())
                level = AdesLevel.T
            },
        )

        response.status shouldBe 200
        response.results shouldHaveSize 2
        response.results.forEach { item ->
            item.status shouldBe 200
            item.level shouldBe AdesLevel.T
            // Каждый элемент — самостоятельная подпись, а не кусок общей.
            cadesService.verify(
                CadesVerifyRequest().apply { cms = item.cms.shouldNotBeNull() },
            ).valid shouldBe true
        }
    }

    test("signBatch keeps going when one item is not valid base64") {
        val response = cadesService.signBatch(
            CadesSignBatchRequest().apply {
                data = listOf(payload, "не base64 вовсе", payload)
                signers = listOf(signer())
            },
        )

        // Top-level 200 означает «batch дошёл до конца», а не «всё удалось».
        response.status shouldBe 200
        response.results shouldHaveSize 3
        response.results[0].status shouldBe 200
        response.results[1].status shouldBe 400
        response.results[1].cms.shouldBeNull()
        response.results[2].status shouldBe 200
    }

    test("verifyBatch verifies each item on its own, detached included") {
        val attached = cadesService.sign(request()).cms.shouldNotBeNull()
        val detached = cadesService.sign(request(detached = true)).cms.shouldNotBeNull()

        val response = cadesService.verifyBatch(
            CadesVerifyBatchRequest().apply {
                items = listOf(
                    CadesVerifyBatchRequest.Item().apply { cms = attached },
                    CadesVerifyBatchRequest.Item().apply {
                        cms = detached
                        data = payload
                    },
                )
            },
        )

        response.results shouldHaveSize 2
        response.results.forEach { it.valid shouldBe true }
    }

    test("verifyBatch reports a broken item without spoiling the others") {
        val signed = cadesService.sign(request()).cms.shouldNotBeNull()

        val response = cadesService.verifyBatch(
            CadesVerifyBatchRequest().apply {
                items = listOf(
                    CadesVerifyBatchRequest.Item().apply { cms = signed },
                    CadesVerifyBatchRequest.Item().apply { cms = "не CMS" },
                )
            },
        )

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        response.results[1].valid shouldBe false
        response.results[1].status shouldBe 400
    }

    // ---- доподписание (PATCH /cades/sign) ----

    fun coSignRequest(cms: String, level: AdesLevel = AdesLevel.B, data: String? = null) =
        CadesSignRequest().apply {
            this.cms = cms
            this.data = data
            this.signers = listOf(
                SignerRequest().apply {
                    key = TestResources.loadAsBase64("p12/legal_ceo_valid.p12")
                    password = TestResources.P12_PASSWORD
                },
            )
            this.level = level
        }

    test("coSign adds a second signer with full AdES attributes") {
        val first = cadesService.sign(request()).cms.shouldNotBeNull()
        val both = cadesService.coSign(coSignRequest(first)).cms.shouldNotBeNull()

        val result = cadesService.verify(CadesVerifyRequest().apply { cms = both })
        result.valid shouldBe true
        result.signers.size shouldBe 2

        // Новый подписант — полноценный AdES, а не «просто ещё один SignerInfo»:
        // без привязки к сертификату документ перестал бы быть CAdES.
        val signers = CMSSignedData(Base64.getDecoder().decode(both)).signerInfos.signers
            .map { it as SignerInformation }
        signers.size shouldBe 2
        signers.forEach {
            it.signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2).shouldNotBeNull()
        }
    }

    test("coSign keeps the first signer's timestamp untouched") {
        val first = cadesService.sign(request(level = AdesLevel.T)).cms.shouldNotBeNull()
        val originalToken = firstSigner(first).unsignedAttributes
            .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).attrValues.getObjectAt(0).getDERObject().getDEREncoded()

        val both = cadesService.coSign(coSignRequest(first, AdesLevel.T)).cms.shouldNotBeNull()
        val signers = CMSSignedData(Base64.getDecoder().decode(both)).signerInfos.signers
            .map { it as SignerInformation }

        // У прежнего подписанта ровно та же метка — не вторая поверх и не новая
        // вместо: свидетельствовать о чужом времени задним числом мы не вправе.
        val kept = signers.map { it.unsignedAttributes?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) }
            .filterNotNull()
        kept.size shouldBe 2
        kept.count { it.attrValues.getObjectAt(0).getDERObject().getDEREncoded().contentEquals(originalToken) } shouldBe 1
        kept.forEach { it.attrValues.size() shouldBe 1 }

        cadesService.verify(CadesVerifyRequest().apply { cms = both }).valid shouldBe true
    }

    test("coSign preserves the embedded validation data of level LT") {
        // Ровно та ловушка, что есть у старого PATCH /cms/sign: он пересобирает
        // SignedData и теряет поле crls, где живёт материал уровня LT. Подпись
        // остаётся валидной и молча перестаёт быть долгоживущей.
        val first = cadesService.sign(request(level = AdesLevel.LT)).cms.shouldNotBeNull()
        val embedded = CmsValidationData.extract(Base64.getDecoder().decode(first))
        (embedded.crls.size + embedded.ocspResponses.size) shouldBeGreaterThan 0

        val both = cadesService.coSign(coSignRequest(first, AdesLevel.LT)).cms.shouldNotBeNull()
        val after = CmsValidationData.extract(Base64.getDecoder().decode(both))

        after.crls.size shouldBeGreaterThanOrEqual embedded.crls.size
        after.ocspResponses.size shouldBeGreaterThanOrEqual embedded.ocspResponses.size

        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = both
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )
        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LT
    }

    test("coSign reports the document level as the weakest signer") {
        // Первый подписал на T, второй — на B: документ не сильнее слабого звена,
        // и отдавать запрошенный уровень было бы неправдой.
        val first = cadesService.sign(request(level = AdesLevel.T)).cms.shouldNotBeNull()
        val both = cadesService.coSign(coSignRequest(first, AdesLevel.B))

        both.level shouldBe AdesLevel.B
        cadesService.verify(CadesVerifyRequest().apply { cms = both.cms!! }).signers
            .map { it.level }.toSet() shouldBe setOf(AdesLevel.B, AdesLevel.T)
    }

    test("coSign gives the new signer its own archive timestamp and leaves the old one alone") {
        val first = cadesService.sign(request(level = AdesLevel.LTA)).cms.shouldNotBeNull()
        val both = cadesService.coSign(coSignRequest(first, AdesLevel.LTA)).cms.shouldNotBeNull()

        CMSSignedData(Base64.getDecoder().decode(both)).signerInfos.signers
            .map { it as SignerInformation }
            .forEach { signer ->
                // По одной архивной метке на подписанта: у прежнего — прежняя.
                signer.unsignedAttributes.shouldNotBeNull()
                    .get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3).shouldNotBeNull()
                    .attrValues.size() shouldBe 1
            }

        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = both
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )
        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LTA
    }

    test("coSign of a detached container needs the data") {
        val detached = cadesService.sign(request(detached = true)).cms.shouldNotBeNull()

        shouldThrow<ClientException> { cadesService.coSign(coSignRequest(detached)) }

        val both = cadesService.coSign(coSignRequest(detached, data = payload)).cms.shouldNotBeNull()
        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = both
                data = payload
            },
        )
        result.valid shouldBe true
        result.signers.size shouldBe 2
    }

    test("coSign without a container is a client error") {
        shouldThrow<ClientException> {
            cadesService.coSign(CadesSignRequest().apply { signers = listOf(signer()) })
        }
    }

    test("archive timestamp of a co-signer is built over its own SignerInfo") {
        // Один и тот же ключ подписывает дважды — «за себя и как руководитель».
        // SID у таких подписей совпадает, и поиск SignerInfo по нему выдавал бы
        // обеим первую. Метка, посчитанная не над своим SignerInfo, у нас же и
        // сойдётся (ту же ошибку повторит проверка), а чужой валидатор её
        // отвергнет — что и произошло на живом NCALayer.
        val first = cadesService.sign(request()).cms.shouldNotBeNull()
        val both = cadesService.coSign(
            CadesSignRequest().apply {
                cms = first
                signers = listOf(signer())
            },
        ).cms.shouldNotBeNull()

        val cms = CMSSignedData(Base64.getDecoder().decode(both))
        val signers = cms.signerInfos.signers.map { it as SignerInformation }
        signers.size shouldBe 2
        // Ключ один — значит и SID один на двоих, иначе тест ничего не ловит.
        signers.map { it.sid.serialNumber }.toSet().size shouldBe 1

        val digestOid = getTspHashAlgorithmByOid(signerCertificate.sigAlgOID)
        signers.forEach { signerInfo ->
            val hashIndex = CmsArchiveTimestamp.hashIndex(cms, signerInfo, digestOid, provider)
            val input = CmsArchiveTimestamp.imprintInput(
                cms, signerInfo, digestOid, hashIndex, provider, Base64.getDecoder().decode(payload),
            )
            // В расчёт метки должно попасть значение подписи ИМЕННО этого
            // подписанта — по нему и различаются одноимённые SignerInfo.
            containsBytes(input, signerInfo.signature) shouldBe true
        }
    }

    test("archive timestamp of a detached signature covers the real content") {
        // У отсоединённой подписи содержимого в контейнере нет. Если подставить
        // вместо него пустоту, метка сойдётся только у нас: свой же неверный
        // расчёт мы повторим и при проверке. Внешний проверяющий, у которого
        // данные есть, её отвергнет — так и произошло на живом NCALayer.
        val signed = cadesService.sign(request(level = AdesLevel.LTA, detached = true)).cms.shouldNotBeNull()
        val data = Base64.getDecoder().decode(payload)

        val cms = CMSSignedData(CMSProcessableByteArray(data), Base64.getDecoder().decode(signed))
        val signerInfo = cms.signerInfos.signers.first() as SignerInformation

        val archive = signerInfo.unsignedAttributes.shouldNotBeNull()
            .get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3).shouldNotBeNull()
        val token = CMSSignedData(archive.attrValues.getObjectAt(0).getDERObject().getDEREncoded())
        val hashIndex = (token.signerInfos.signers.first() as SignerInformation)
            .unsignedAttributes.shouldNotBeNull().get(CmsArchiveTimestamp.ATS_HASH_INDEX_V3).shouldNotBeNull()

        // Пересчитываем imprint так, как это сделает сторонний проверяющий:
        // по настоящим данным, которые он получил отдельным файлом.
        val digestOid = getTspHashAlgorithmByOid(signerCertificate.sigAlgOID)
        val input = CmsArchiveTimestamp.imprintInput(cms, signerInfo, digestOid, hashIndex, provider, data)
        tspService.verify(token, input, false, false).shouldNotBeNull()

        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                this.cms = signed
                this.data = payload
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )
        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LTA
    }

    test("detached signature without the data is a client error, not a verdict") {
        // Пересчитать нечего — ни подпись, ни метку. Отвечать «недействительна»
        // было бы неправдой: мы не проверили, а не проверили и отвергли.
        val signed = cadesService.sign(request(level = AdesLevel.LTA, detached = true)).cms.shouldNotBeNull()

        shouldThrow<ClientException> {
            cadesService.verify(CadesVerifyRequest().apply { this.cms = signed })
        }
    }

    test("ATSHashIndex of every signer matches the final container") {
        // Внешний проверяющий сверяет индекс архивной метки с тем, что реально
        // лежит в контейнере. Если после расчёта метки контейнер изменился —
        // например, пересобрался при подстановке подписантов — индекс начнёт
        // ссылаться на то, чего уже нет, и метка будет отвергнута. Своя
        // проверка этого не ловит: она берёт индекс из самой метки.
        val first = cadesService.sign(request(level = AdesLevel.LTA)).cms.shouldNotBeNull()
        val both = cadesService.coSign(
            CadesSignRequest().apply {
                cms = first
                signers = listOf(signer())
                level = AdesLevel.LTA
            },
        ).cms.shouldNotBeNull()

        val bytes = Base64.getDecoder().decode(both)
        val signedData = SignedData.getInstance(
            ContentInfo.getInstance(ASN1Object.fromByteArray(bytes)).content,
        )
        val present = mutableListOf<ByteArray>()
        fun collect(set: ASN1Set?) {
            if (set == null) return
            for (index in 0 until set.size()) {
                present.add(set.getObjectAt(index).getDERObject().getDEREncoded())
            }
        }
        collect(signedData.certificates)
        collect(signedData.getCRLs())

        val signers = CMSSignedData(bytes).signerInfos.signers.map { it as SignerInformation }
        signers.forEach { signerInfo ->
            val archive = signerInfo.unsignedAttributes.shouldNotBeNull()
                .get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3).shouldNotBeNull()
            val token = CMSSignedData(archive.attrValues.getObjectAt(0).getDERObject().getDEREncoded())
            val hashIndex = (token.signerInfos.signers.first() as SignerInformation)
                .unsignedAttributes.shouldNotBeNull().get(CmsArchiveTimestamp.ATS_HASH_INDEX_V3).shouldNotBeNull()

            val index = ASN1Sequence.getInstance(hashIndex.attrValues.getObjectAt(0))
            val digestOid = AlgorithmIdentifier.getInstance(index.getObjectAt(0)).objectId.id
            val digest = MessageDigest.getInstance(digestOid, provider)

            // certificatesHashIndex и crlsHashIndex — каждый хэш обязан
            // соответствовать элементу, который в контейнере есть.
            listOf(1, 2).forEach { position ->
                val hashes = ASN1Sequence.getInstance(index.getObjectAt(position))
                for (i in 0 until hashes.size()) {
                    val wanted = (hashes.getObjectAt(i).getDERObject() as DEROctetString).octets
                    val found = present.any { digest.digest(it).contentEquals(wanted) }
                    found shouldBe true
                }
            }
        }
    }

    test("verify reports the ETSI status alongside the flag") {
        // Флаг valid говорит «принята или нет», а статус — почему. На здоровой
        // подписи причины нет вовсе: пустое поле честнее, чем формальная
        // отписка.
        val signed = cadesService.sign(request(level = AdesLevel.T)).cms.shouldNotBeNull()
        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = signed
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.validationStatus shouldBe AdesValidationStatus.VALID
        result.subIndication.shouldBeNull()
        result.signers.single().validationStatus shouldBe AdesValidationStatus.VALID
    }

    test("a tampered signature is reported as a crypto failure, not just false") {
        val signed = cadesService.sign(request()).cms.shouldNotBeNull()
        val bytes = Base64.getDecoder().decode(signed)
        // Портим значение подписи: сертификат при этом остаётся здоровым, и
        // причина должна указывать именно на криптографию.
        bytes[bytes.size - 5] = (bytes[bytes.size - 5].toInt() xor 0xFF).toByte()

        val result = cadesService.verify(
            CadesVerifyRequest().apply { cms = Base64.getEncoder().encodeToString(bytes) },
        )

        result.valid shouldBe false
        result.validationStatus shouldBe AdesValidationStatus.INVALID
        result.subIndication shouldBe AdesSubIndication.SIG_CRYPTO_FAILURE
    }
})
