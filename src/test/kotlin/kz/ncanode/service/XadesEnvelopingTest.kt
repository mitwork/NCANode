package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.SignaturePackaging
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.wrapper.DocumentWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.w3c.dom.Element

/**
 * XAdES с документом внутри подписи (`ENVELOPING`).
 *
 * В интерфейсе NCALayer это «присоединённая (содержимое внутри)», и такие
 * файлы приходят от их пользователей. Корнем документа становится
 * `ds:Signature`, а исходное содержимое лежит в `ds:Object` и подписывается
 * по ссылке на него.
 */
@SpringBootTest
@ActiveProfiles("test")
class XadesEnvelopingTest(
    @param:Autowired private val xadesService: XadesService,
    @param:Autowired private val xmlService: XmlService,
) : FunSpec({

    val xml = """<?xml version="1.0" encoding="UTF-8"?><document><data>payload</data></document>"""
    val dsNamespace = "http://www.w3.org/2000/09/xmldsig#"

    fun signerRequest(name: String = "individual_valid.p12") = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/$name")
        password = TestResources.P12_PASSWORD
    }

    fun sign(level: AdesLevel = AdesLevel.B, signers: List<SignerRequest> = listOf(signerRequest())) =
        xadesService.sign(
            XadesSignRequest().apply {
                this.xml = xml
                this.signers = signers
                this.level = level
                this.packaging = SignaturePackaging.ENVELOPING
            },
        )

    test("the signature becomes the root and carries the document inside") {
        val signed = sign().xml.shouldNotBeNull()
        val document = DocumentWrapper(signed).document

        document.documentElement.localName shouldBe "Signature"
        document.documentElement.namespaceURI shouldBe dsNamespace

        // Содержимое — внутри ds:Object, на который и ссылается подпись.
        val objects = document.getElementsByTagNameNS(dsNamespace, "Object")
        val payloadObject = (0 until objects.length)
            .map { objects.item(it) as Element }
            .single { it.getAttribute("Id").endsWith("-obj0") }
        payloadObject.getElementsByTagName("data").length shouldBe 1
    }

    test("such a signature verifies, and the coverage rule accepts it") {
        // Требование «покрывать весь документ» здесь выполняется иначе: вне
        // подписи ничего нет, покрыт должен быть объект с содержимым.
        val signed = sign().xml.shouldNotBeNull()

        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = signed })
        result.valid shouldBe true
        result.signatures.size shouldBe 1
        result.level shouldBe AdesLevel.B

        xmlService.verify(signed, checkOcsp = false, checkCrl = false).valid shouldBe true
    }

    test("tampering with the enclosed content breaks verification") {
        val signed = sign().xml.shouldNotBeNull()
        val tampered = signed.replace("<data>payload</data>", "<data>подменено</data>")

        xadesService.verify(XadesVerifyRequest().apply { this.xml = tampered }).valid shouldBe false
    }

    test("level T works the same way") {
        val signed = sign(AdesLevel.T).xml.shouldNotBeNull()
        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = signed })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.T
        result.verifiedLevel shouldBe AdesLevel.T
    }

    test("two signers are refused: a document has a single root") {
        shouldThrow<ClientException> {
            sign(signers = listOf(signerRequest(), signerRequest("legal_ceo_valid.p12")))
        }
    }
})
