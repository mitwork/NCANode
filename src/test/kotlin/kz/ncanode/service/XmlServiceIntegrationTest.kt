package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kz.ncanode.TestResources
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XmlSignBatchRequest
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.request.XmlVerifyBatchRequest
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.w3c.dom.Element

@SpringBootTest
@ActiveProfiles("test")
class XmlServiceIntegrationTest(
    @param:Autowired private val xmlService: XmlService,
    @param:Autowired private val caService: CaService,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec { caService.updateCache(true) }

    fun signerOf(p12: String) = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/$p12")
        password = TestResources.P12_PASSWORD
    }

    // Собирает ds:Signature-элемент с заданным URI Reference'а (структура без
    // валидной крипты — coversWholeDocument смотрит только на SignedInfo).
    fun signatureElement(referenceUri: String): Element {
        val xml = """
            <root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <data>payload</data>
              <ds:Signature>
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                  <ds:Reference URI="$referenceUri">
                    <ds:Transforms>
                      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                      <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ds:DigestValue>AAAA</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AAAA</ds:SignatureValue>
              </ds:Signature>
            </root>
        """.trimIndent()
        return DocumentWrapper(xml).document
            .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature")
            .item(0) as Element
    }

    // --- Audit fix 2.1: whole-document coverage (anti XML Signature Wrapping) ---
    test("coversWholeDocument: empty-URI enveloped reference is whole-document") {
        XMLSignatureWrapper(signatureElement("")).coversWholeDocument() shouldBe true
    }

    test("coversWholeDocument: sub-element reference (#x) is NOT whole-document") {
        XMLSignatureWrapper(signatureElement("#x")).coversWholeDocument() shouldBe false
    }

    test("sign + verify XML roundtrip (no TSP / no revocation)") {
        val request = XmlSignRequest().apply {
            xml = """<?xml version="1.0" encoding="UTF-8"?><root><data>hello</data></root>"""
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val signed = xmlService.sign(request)
        signed.xml.shouldNotBeNull()

        val verification = xmlService.verify(signed.xml!!, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
    }

    test("verify: tampered content after signing → valid=false (digest must be checked)") {
        // Крипто-негатив: без реальной проверки дайджеста Reference'а этот тест
        // прошёл бы как valid=true. Подписываем, затем портим содержимое <data>.
        val signed = xmlService.sign(XmlSignRequest().apply {
            xml = """<?xml version="1.0" encoding="UTF-8"?><root><data>hello</data></root>"""
            signers = listOf(signerOf("individual_valid.p12"))
        }).xml!!
        val tampered = signed.replace("hello", "haxed")
        tampered shouldNotBe signed // замена реально произошла — иначе тест пуст

        xmlService.verify(tampered, checkOcsp = false, checkCrl = false).valid shouldBe false
    }

    test("multi-signer XML: two signers, two ds:Signature elements, both verify") {
        val request = XmlSignRequest().apply {
            xml = """<?xml version="1.0" encoding="UTF-8"?><root><data>multi</data></root>"""
            signers = listOf(
                signerOf("individual_valid.p12"),
                signerOf("legal_ceo_valid.p12"),
            )
        }
        val signed = xmlService.sign(request)
        val verification = xmlService.verify(signed.xml!!, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 2
    }

    test("trimXml removes whitespace text nodes before signing") {
        val request = XmlSignRequest().apply {
            xml = """<?xml version="1.0"?>
                <root>
                    <data>  trimmed  </data>
                </root>""".trimIndent()
            signers = listOf(signerOf("individual_valid.p12"))
            isTrimXml = true
        }
        val signed = xmlService.sign(request)
        // После trimXml межтеговые пробелы убираются, но valid сигнатура
        // должна получиться по обработанному xml.
        val verification = xmlService.verify(signed.xml!!, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
    }

    test("verify with OCSP returns invalid for revoked signer") {
        val request = XmlSignRequest().apply {
            xml = """<?xml version="1.0"?><root><x/></root>"""
            signers = listOf(signerOf("individual_revoked.p12"))
        }
        val signed = xmlService.sign(request)
        val verification = xmlService.verify(signed.xml!!, checkOcsp = true, checkCrl = false)
        verification.valid shouldBe false
    }

    test("signBatch: all items signed independently, each verifiable") {
        val request = XmlSignBatchRequest().apply {
            xmls = listOf(
                """<?xml version="1.0"?><doc id="1"><data>a</data></doc>""",
                """<?xml version="1.0"?><doc id="2"><data>b</data></doc>""",
                """<?xml version="1.0"?><doc id="3"><data>c</data></doc>""",
            )
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val response = xmlService.signBatch(request)

        response.results shouldHaveSize 3
        response.results.forEach {
            it.status shouldBe 200
            it.xml.shouldNotBeNull()
        }
        // Каждый подписанный XML должен независимо верифицироваться.
        response.results.forEach { item ->
            xmlService.verify(item.xml!!, checkOcsp = false, checkCrl = false).valid shouldBe true
        }
    }

    test("verifyBatch: all items verified independently, valid flag per item") {
        // Знаем что individual_valid даёт valid=true; sign + verifyBatch на
        // массиве из трёх подписанных документов.
        val signRequest = XmlSignBatchRequest().apply {
            xmls = listOf(
                """<?xml version="1.0"?><doc><x>a</x></doc>""",
                """<?xml version="1.0"?><doc><x>b</x></doc>""",
            )
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val signed = xmlService.signBatch(signRequest)

        val verifyRequest = XmlVerifyBatchRequest().apply {
            xmls = signed.results.map { it.xml!! }
        }
        val verified = xmlService.verifyBatch(verifyRequest)

        verified.results shouldHaveSize 2
        verified.results.forEach { it.valid shouldBe true }
    }

    test("verifyBatch: partial response — malformed XML returns 500 item, others verified") {
        val signedOne = xmlService.sign(XmlSignRequest().apply {
            xml = """<?xml version="1.0"?><doc><x>ok</x></doc>"""
            signers = listOf(signerOf("individual_valid.p12"))
        })

        val request = XmlVerifyBatchRequest().apply {
            xmls = listOf(
                signedOne.xml!!,
                "<unclosed",  // невалидный XML
            )
        }
        val response = xmlService.verifyBatch(request)

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        response.results[1].valid shouldBe false
        response.results[1].status shouldBe 500
    }

    test("verifyBatch: OCSP/CRL flags forwarded to each per-item verify") {
        // Один подписан revoked-ключом; с OCSP=true должен дать valid=false.
        val signedOk = xmlService.sign(XmlSignRequest().apply {
            xml = """<?xml version="1.0"?><doc><x>ok</x></doc>"""
            signers = listOf(signerOf("individual_valid.p12"))
        })
        val signedRevoked = xmlService.sign(XmlSignRequest().apply {
            xml = """<?xml version="1.0"?><doc><x>revoked</x></doc>"""
            signers = listOf(signerOf("individual_revoked.p12"))
        })

        val response = xmlService.verifyBatch(XmlVerifyBatchRequest().apply {
            xmls = listOf(signedOk.xml!!, signedRevoked.xml!!)
            revocationCheck = setOf(CertificateRevocation.OCSP)
        })

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        response.results[1].valid shouldBe false
    }

    test("signBatch: partial response — bad XML in middle doesn't kill the rest") {
        // Второй item — невалидный XML. Первый и третий должны успешно подписаться,
        // у второго — status 4xx/5xx с readable error message.
        val request = XmlSignBatchRequest().apply {
            xmls = listOf(
                """<?xml version="1.0"?><doc><data>ok-1</data></doc>""",
                """<?xml version="1.0"?><doc><unclosed""",  // syntax error
                """<?xml version="1.0"?><doc><data>ok-3</data></doc>""",
            )
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val response = xmlService.signBatch(request)

        response.results shouldHaveSize 3
        response.results[0].status shouldBe 200
        response.results[0].xml.shouldNotBeNull()
        // Невалидный XML — ServerException(500) от парсера в DocumentWrapper'е.
        response.results[1].status shouldBe 500
        response.results[1].xml shouldBe null
        response.results[2].status shouldBe 200
        response.results[2].xml.shouldNotBeNull()
    }
})
