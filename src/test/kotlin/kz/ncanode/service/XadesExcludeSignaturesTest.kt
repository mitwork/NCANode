package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.w3c.dom.Element

/**
 * Режим `ncanode.xades.excludeSignatures` — ссылка исключает ВСЕ подписи.
 *
 * Обычный `enveloped-signature` вырезает из покрытия только свою подпись,
 * поэтому добавленная позже вторая подпись попадает в покрытие первой. Мы это
 * переживаем — снимаем более поздние подписи при проверке, — а проверяющие,
 * которые так не делают, объявляют первую подпись недействительной. Здесь
 * проверяется альтернатива: покрытие, не зависящее от числа подписей.
 */
@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = ["ncanode.xades.excludeSignatures=true"])
class XadesExcludeSignaturesTest(
    @param:Autowired private val xadesService: XadesService,
    @param:Autowired private val xmlService: XmlService,
) : FunSpec({

    val xml = """<?xml version="1.0" encoding="UTF-8"?><document><data>payload</data></document>"""

    fun signerRequest(name: String = "individual_valid.p12") = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/$name")
        password = TestResources.P12_PASSWORD
    }

    fun sign(source: String, signer: String) = xadesService.sign(
        XadesSignRequest().apply {
            this.xml = source
            this.signers = listOf(signerRequest(signer))
            this.level = AdesLevel.B
        },
    ).xml.shouldNotBeNull()

    test("the reference excludes signatures instead of just its own") {
        val signed = sign(xml, "individual_valid.p12")
        val document = DocumentWrapper(signed)
        val nodes = document.document.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#", "XPath",
        )
        nodes.length shouldBe 1
        (nodes.item(0) as Element).textContent.trim() shouldBe
            XMLSignatureWrapper.EXCLUDE_ALL_SIGNATURES_XPATH
    }

    test("a second signature does not break the first one") {
        // Главное свойство режима: покрытие первой подписи не зависит от того,
        // сколько подписей добавят после неё.
        val first = sign(xml, "individual_valid.p12")
        val both = sign(first, "legal_ceo_valid.p12")

        val document = DocumentWrapper(both)
        document.document.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#", "Signature",
        ).length shouldBe 2

        val result = xadesService.verify(XadesVerifyRequest().apply { this.xml = both })
        result.valid shouldBe true
        result.signatures.size shouldBe 2
    }

    test("each signature verifies on its own, without peeling the later ones") {
        // Проверяющий, который не снимает более поздние подписи, должен принять
        // обе. Эмулируем его: проверяем документ как есть, подпись за подписью.
        val both = sign(sign(xml, "individual_valid.p12"), "legal_ceo_valid.p12")
        val document = DocumentWrapper(both)
        val signatures = document.document.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#", "Signature",
        )

        (0 until signatures.length).forEach { index ->
            val wrapper = XMLSignatureWrapper(signatures.item(index) as Element)
            wrapper.certificate.shouldNotBeNull()
            wrapper.check() shouldBe true
            wrapper.coversWholeDocument() shouldBe true
        }

        // И обычный /xml/verify тоже принимает такой документ.
        xmlService.verify(both, checkOcsp = false, checkCrl = false).valid shouldBe true
    }
})
