package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XmlSignRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

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
})
