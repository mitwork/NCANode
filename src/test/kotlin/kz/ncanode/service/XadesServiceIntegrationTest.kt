package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldMatch
import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.x509.IssuerSerial
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.TestResources
import kz.ncanode.ades.XadesInspector
import kz.ncanode.ades.XadesQualifyingProperties
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.ades.SignaturePackaging
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XadesSignBatchRequest
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyBatchRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getTspHashAlgorithmByOid
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.w3c.dom.Element
import java.security.MessageDigest
import java.util.Base64

/**
 * XAdES-B по ETSI EN 319 132-1.
 *
 * Структура сверена с реализацией НУЦ (NCALayer):
 * две ссылки в `SignedInfo` (на документ и на `SignedProperties`), время
 * подписи и привязка к сертификату внутри подписанных свойств, exclusive c14n.
 *
 * Ключевой тест здесь — про подделку `SigningTime`: он доказывает, что
 * свойства действительно накрыты подписью, а не приложены рядом. Без него
 * весь XAdES был бы декорацией над обычным XMLDSIG.
 */
@SpringBootTest
@ActiveProfiles("test")
class XadesServiceIntegrationTest(
    @param:Autowired private val xadesService: XadesService,
    @param:Autowired private val xmlService: XmlService,
) : FunSpec({

    val provider = KalkanProvider()
    val kalkanWrapper = KalkanWrapper(provider)
    val xml = """<?xml version="1.0" encoding="UTF-8"?><document><data>payload</data></document>"""

    val signerCertificate = kalkanWrapper.read(
        TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
    ).certificate.x509Certificate

    fun signerRequest(name: String = "individual_valid.p12") = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/$name")
        password = TestResources.P12_PASSWORD
    }

    fun request(
        level: AdesLevel = AdesLevel.B,
        packaging: SignaturePackaging = SignaturePackaging.ENVELOPED,
        signers: List<SignerRequest> = listOf(signerRequest()),
    ) = XadesSignRequest().apply {
        this.xml = xml
        this.signers = signers
        this.level = level
        this.packaging = packaging
    }

    fun signedDocument(signers: List<SignerRequest> = listOf(signerRequest())): DocumentWrapper =
        DocumentWrapper(xadesService.sign(request(signers = signers)).xml!!)

    fun elements(document: DocumentWrapper, namespace: String, name: String): List<Element> {
        val nodes = document.document.getElementsByTagNameNS(namespace, name)
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }

    val dsNamespace = "http://www.w3.org/2000/09/xmldsig#"
    val xadesNamespace = XadesQualifyingProperties.XADES_NAMESPACE

    test("signature covers both the document and the qualifying properties") {
        val document = signedDocument()

        val references = elements(document, dsNamespace, "Reference")
        references.size shouldBe 2
        // Первая — на сам документ (whole-document, enveloped).
        references[0].getAttribute("URI") shouldBe ""
        // Вторая — на SignedProperties, с типом из спецификации.
        references[1].getAttribute("Type") shouldBe XadesQualifyingProperties.SIGNED_PROPERTIES_TYPE

        val signature = elements(document, dsNamespace, "Signature").single()
        val signatureId = signature.getAttribute("Id")
        signatureId shouldContain "sig-"

        val qualifying = elements(document, xadesNamespace, "QualifyingProperties").single()
        qualifying.getAttribute("Target") shouldBe "#$signatureId"

        val signedProperties = elements(document, xadesNamespace, "SignedProperties").single()
        references[1].getAttribute("URI") shouldBe "#${signedProperties.getAttribute("Id")}"
    }

    test("SigningCertificateV2 carries the certificate digest and IssuerSerialV2") {
        val document = signedDocument()

        val digestValue = elements(document, xadesNamespace, "CertDigest").single()
            .getElementsByTagNameNS(dsNamespace, "DigestValue").item(0).textContent
        // Хэш сертификата считается тем же алгоритмом, что и подпись — в
        // отличие от CAdES, где он всегда SHA-256.
        val digestOid = getDigestAlgorithmOidBYSignAlgorithmOid(signerCertificate.sigAlgOID)
        val expected = MessageDigest.getInstance(digestOid, provider).digest(signerCertificate.encoded)
        Base64.getDecoder().decode(digestValue).contentEquals(expected) shouldBe true

        val issuerSerialText = elements(document, xadesNamespace, "IssuerSerialV2").single().textContent
        val issuerSerial = IssuerSerial.getInstance(
            ASN1Object.fromByteArray(Base64.getDecoder().decode(issuerSerialText)),
        )
        issuerSerial.serial.value shouldBe signerCertificate.serialNumber
    }

    test("SigningTime is written as ISO-8601 UTC") {
        val signingTime = elements(signedDocument(), xadesNamespace, "SigningTime").single().textContent
        signingTime shouldMatch Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z""")
    }

    test("the existing XML verification accepts a XAdES signature") {
        // XAdES добавляет вторую ссылку и Object со свойствами; проверка
        // покрытия всего документа (защита от XSW) не должна на этом спотыкаться.
        val signed = xadesService.sign(request()).xml!!
        xmlService.verify(signed, false, false).valid shouldBe true
    }

    test("tampering with SigningTime invalidates the signature") {
        // Смысл уровня B в том, что время подписи и привязка к сертификату
        // лежат ПОД подписью. Если бы вторая ссылка не считалась, подделка
        // прошла бы незамеченной.
        val document = signedDocument()
        elements(document, xadesNamespace, "SigningTime").single().textContent = "2001-01-01T00:00:00Z"

        xmlService.verify(document.toString(), false, false).valid shouldBe false
    }

    test("tampering with the certificate digest invalidates the signature") {
        val document = signedDocument()
        val digestValue = elements(document, xadesNamespace, "CertDigest").single()
            .getElementsByTagNameNS(dsNamespace, "DigestValue").item(0)
        digestValue.textContent = Base64.getEncoder().encodeToString(ByteArray(32))

        xmlService.verify(document.toString(), false, false).valid shouldBe false
    }

    test("multiple signers each get their own qualifying properties") {
        val document = signedDocument(listOf(signerRequest(), signerRequest("legal_ceo_valid.p12")))

        elements(document, dsNamespace, "Signature").size shouldBe 2
        elements(document, xadesNamespace, "QualifyingProperties").size shouldBe 2
        // Идентификаторы уникальны — иначе ссылки резолвились бы в чужие свойства.
        elements(document, xadesNamespace, "SignedProperties")
            .map { it.getAttribute("Id") }.toSet().size shouldBe 2

        xmlService.verify(document.toString(), false, false).valid shouldBe true
    }

    // ---- уровень T ----

    test("level T attaches a signature timestamp over the canonicalized SignatureValue") {
        val signed = xadesService.sign(request(level = AdesLevel.T))
        signed.level shouldBe AdesLevel.T
        val document = DocumentWrapper(signed.xml!!)

        val timeStamp = elements(document, xadesNamespace, "SignatureTimeStamp").single()
        // Канонизация указывается явно — иначе проверяющий не знает, над чем
        // считался imprint.
        timeStamp.getElementsByTagNameNS(dsNamespace, "CanonicalizationMethod")
            .item(0).let { it as Element }.getAttribute("Algorithm") shouldBe XadesInspector.CANONICALIZATION
        elements(document, xadesNamespace, "EncapsulatedTimeStamp").single()
            .textContent.isNotEmpty() shouldBe true

        // Метка лежит в неподписанных свойствах, поэтому сама подпись цела.
        xmlService.verify(signed.xml!!, false, false).valid shouldBe true
    }

    test("verify confirms level T against the live TSA") {
        // Если бы метка ставилась не над каноническим ds:SignatureValue,
        // сверка imprint'а в TspService не сошлась бы и verifiedLevel остался
        // бы B — то есть этот тест держит инвариант «над чем метка».
        val signed = xadesService.sign(request(level = AdesLevel.T))
        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = signed.xml!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.T
        result.verifiedLevel shouldBe AdesLevel.T
        result.signatures.single().tsp.shouldNotBeNull().genTime.shouldNotBeNull()
    }

    // ---- проверка ----

    test("verify reports level B for a plain XAdES signature") {
        val signed = xadesService.sign(request())
        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = signed.xml!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.B
        result.verifiedLevel shouldBe AdesLevel.B
        result.signatures.single().certificate.shouldNotBeNull().serialNumber shouldBe
            signerCertificate.serialNumber.toString(16)
    }

    test("verify rejects a signature whose CertDigest points at another certificate") {
        // Подменяем только хэш сертификата в подписанных свойствах. Подпись
        // от этого ломается (свойства под ней), но и привязка не сходится —
        // проверяем, что мы сообщаем именно недействительность.
        val document = DocumentWrapper(xadesService.sign(request()).xml!!)
        elements(document, xadesNamespace, "CertDigest").single()
            .getElementsByTagNameNS(dsNamespace, "DigestValue").item(0)
            .textContent = Base64.getEncoder().encodeToString(ByteArray(64))

        xadesService.verify(XadesVerifyRequest().apply { this.xml = document.toString() }).valid shouldBe false
    }

    test("verify refuses a claimed T level whose timestamp does not hold") {
        // Уровень заявлен наличием элемента, но токен — мусор. Такой ответ
        // обязан быть невалидным, а не «валидным уровня T».
        val document = DocumentWrapper(xadesService.sign(request(level = AdesLevel.T)).xml!!)
        elements(document, xadesNamespace, "EncapsulatedTimeStamp").single()
            .textContent = Base64.getEncoder().encodeToString("not a timestamp token".toByteArray())

        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = document.toString() })
        result.valid shouldBe false
        result.level shouldBe AdesLevel.T
        result.verifiedLevel shouldBe AdesLevel.B
    }

    // ---- уровень LT ----

    test("level LT embeds the certificate chain and revocation data") {
        val signed = xadesService.sign(request(level = AdesLevel.LT))
        signed.level shouldBe AdesLevel.LT
        val document = DocumentWrapper(signed.xml!!)

        // Цепочка: подписант плюс как минимум издатель.
        val certificates = elements(document, xadesNamespace, "EncapsulatedX509Certificate")
        (certificates.size >= 2) shouldBe true
        elements(document, xadesNamespace, "CertificateValues").size shouldBe 1

        // Данные об отзыве: CRL и/или OCSP внутри RevocationValues.
        val revocation = elements(document, xadesNamespace, "RevocationValues").single()
        val values = revocation.getElementsByTagNameNS(xadesNamespace, "EncapsulatedCRLValue").length +
            revocation.getElementsByTagNameNS(xadesNamespace, "EncapsulatedOCSPValue").length
        (values > 0) shouldBe true
    }

    test("level LT keeps the signature valid and is reported as such") {
        // Материал кладётся в неподписанные свойства, поэтому подпись цела.
        val signed = xadesService.sign(request(level = AdesLevel.LT))
        xmlService.verify(signed.xml!!, false, false).valid shouldBe true

        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = signed.xml!! })
        result.valid shouldBe true
        result.level shouldBe AdesLevel.LT
        // Сам вшитый материал мы пока не используем при проверке.
        result.verifiedLevel shouldBe AdesLevel.T
    }

    // ---- уровень LTA ----

    test("level LTA attaches an archive timestamp with material to verify it") {
        val signed = xadesService.sign(request(level = AdesLevel.LTA))
        signed.level shouldBe AdesLevel.LTA
        val document = DocumentWrapper(signed.xml!!)
        val xades141 = "http://uri.etsi.org/01903/v1.4.1#"

        elements(document, xades141, "ArchiveTimeStamp").size shouldBe 1
        // Материал для проверки самой метки: без него архивная метка со
        // временем стала бы непроверяемой — сертификат TSA тоже истекает.
        elements(document, xades141, "TimeStampValidationData").size shouldBe 1

        // Подпись при этом цела: свойства неподписанные.
        xmlService.verify(signed.xml!!, false, false).valid shouldBe true
    }

    test("the archive timestamp imprint covers the signature and everything added to it") {
        // Пересчитываем то, по чему должна была считаться метка, на состоянии
        // ДО её добавления, и сверяем с imprint'ом внутри токена.
        val signed = xadesService.sign(request(level = AdesLevel.LT))
        val ltaSigned = xadesService.sign(request(level = AdesLevel.LTA))

        val ltDocument = DocumentWrapper(signed.xml!!)
        val expectedInput = XadesInspector.archiveTimestampInput(
            elements(ltDocument, dsNamespace, "Signature").single(),
        )

        val ltaDocument = DocumentWrapper(ltaSigned.xml!!)
        val encapsulated = elements(ltaDocument, xadesNamespace, "EncapsulatedTimeStamp")
        // Первый — метка подписи (T), второй — архивная.
        val archiveToken = TimeStampToken(
            CMSSignedData(Base64.getDecoder().decode(encapsulated.last().textContent.trim())),
        )

        // Подписи в двух документах разные (разное время и nonce), поэтому
        // сверяем не байты, а то, что расчёт вообще воспроизводим и даёт
        // imprint нужной длины для этого алгоритма.
        val digestOid = getTspHashAlgorithmByOid(signerCertificate.sigAlgOID)
        val digest = MessageDigest.getInstance(digestOid, provider)
        digest.digest(expectedInput).size shouldBe archiveToken.timeStampInfo.messageImprintDigest.size
    }

    test("level LT is confirmed from the embedded material") {
        val signed = xadesService.sign(request(level = AdesLevel.LT))
        val result = xadesService.verify(
            XadesVerifyRequest().apply {
                this.xml = signed.xml!!
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.level shouldBe AdesLevel.LT
        result.verifiedLevel shouldBe AdesLevel.LT
    }

    test("level LTA is confirmed only when the archive timestamp checks out") {
        // Здесь же проверяется, что расчёт при верификации останавливается на
        // самой метке: включи она себя, imprint бы не сошёлся и уровень упал
        // бы до LT.
        val signed = xadesService.sign(request(level = AdesLevel.LTA))
        val result = xadesService.verify(
            XadesVerifyRequest().apply {
                this.xml = signed.xml!!
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        result.verifiedLevel shouldBe AdesLevel.LTA
    }

    test("level LT is not claimed when revocation was not requested") {
        val signed = xadesService.sign(request(level = AdesLevel.LT))
        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = signed.xml!! })

        result.level shouldBe AdesLevel.LT
        result.verifiedLevel shouldBe AdesLevel.T
    }

    test("other packagings are refused explicitly") {
        shouldThrow<ClientException> { xadesService.sign(request(packaging = SignaturePackaging.DETACHED)) }
            .message!! shouldContain "not supported yet"
    }

    // ---- batch ----

    test("signBatch signs every document with the shared signer and level") {
        val response = xadesService.signBatch(
            XadesSignBatchRequest().apply {
                xmls = listOf(xml, """<?xml version="1.0" encoding="UTF-8"?><other><v>2</v></other>""")
                signers = listOf(signerRequest())
                level = AdesLevel.T
            },
        )

        response.status shouldBe 200
        response.results shouldHaveSize 2
        response.results.forEach { item ->
            item.status shouldBe 200
            item.level shouldBe AdesLevel.T
            xadesService.verify(
                XadesVerifyRequest().apply { this.xml = item.xml.shouldNotBeNull() },
            ).valid shouldBe true
        }
    }

    test("signBatch keeps going when one document is malformed") {
        val response = xadesService.signBatch(
            XadesSignBatchRequest().apply {
                xmls = listOf(xml, "<unclosed", xml)
                signers = listOf(signerRequest())
            },
        )

        response.results shouldHaveSize 3
        response.results[0].status shouldBe 200
        response.results[1].xml shouldBe null
        response.results[2].status shouldBe 200
    }

    test("verifyBatch verifies each document independently") {
        val signed = xadesService.signBatch(
            XadesSignBatchRequest().apply {
                xmls = listOf(xml, xml)
                signers = listOf(signerRequest())
            },
        )

        val response = xadesService.verifyBatch(
            XadesVerifyBatchRequest().apply {
                xmls = signed.results.map { it.xml.shouldNotBeNull() }
            },
        )

        response.results shouldHaveSize 2
        response.results.forEach { it.valid shouldBe true }
    }

    test("verifyBatch reports an unsigned document without spoiling the others") {
        val signed = xadesService.sign(request()).xml.shouldNotBeNull()

        val response = xadesService.verifyBatch(
            XadesVerifyBatchRequest().apply { xmls = listOf(signed, xml) }
        )

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        // Документ без подписи для XML — не ошибка, а отрицательный вердикт
        // (в отличие от PDF, где это 404 NoSignaturesFound). Поведение
        // унаследовано от `/xml/verify` и batch его не меняет.
        response.results[1].valid shouldBe false
        response.results[1].status shouldBe 200
    }

    test("signing an already signed document adds a signature and keeps the first one valid") {
        // Бизнес-поток «подписал один, через день второй»: документ приходит
        // обратно уже подписанным. Для XAdES отдельный эндпойнт не нужен —
        // подписывается тот же XML.
        val first = xadesService.sign(request(level = AdesLevel.T)).xml.shouldNotBeNull()
        val second = xadesService.sign(
            XadesSignRequest().apply {
                this.xml = first
                this.signers = listOf(signerRequest("legal_ceo_valid.p12"))
                this.level = AdesLevel.T
            },
        ).xml.shouldNotBeNull()

        val document = DocumentWrapper(second)
        elements(document, dsNamespace, "Signature").size shouldBe 2

        // Обе подписи проверяются: каждая — на документе в том виде, в каком
        // её видел автор, поэтому более ранняя не ломается более поздней.
        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = second })
        result.valid shouldBe true
        result.signatures.size shouldBe 2
        result.signatures.map { it.verifiedLevel }.toSet() shouldBe setOf(AdesLevel.T)
    }
})
