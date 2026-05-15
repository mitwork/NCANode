package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.request.WsseSignRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

@SpringBootTest
@ActiveProfiles("test")
class WsseServiceIntegrationTest(
    @param:Autowired private val wsseService: WsseService,
    @param:Autowired private val caService: CaService,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec { caService.updateCache(true) }

    val sampleSoap = """<?xml version="1.0" encoding="UTF-8"?>
        |<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        |  <soapenv:Body>
        |    <test>payload</test>
        |  </soapenv:Body>
        |</soapenv:Envelope>""".trimMargin()

    test("sign + verify SOAP envelope roundtrip") {
        val signed = wsseService.sign(WsseSignRequest().apply {
            xml = sampleSoap
            key = TestResources.loadAsBase64("p12/individual_valid.p12")
            password = TestResources.P12_PASSWORD
        })
        signed.xml.shouldNotBeNull()

        val verification = wsseService.verify(signed.xml!!, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
    }

    test("verify revoked signer returns invalid when OCSP enabled") {
        val signed = wsseService.sign(WsseSignRequest().apply {
            xml = sampleSoap
            key = TestResources.loadAsBase64("p12/individual_revoked.p12")
            password = TestResources.P12_PASSWORD
        })

        val verification = wsseService.verify(signed.xml!!, checkOcsp = true, checkCrl = false)
        verification.valid shouldBe false
    }

    test("verify envelope without signature returns valid=false, empty signers") {
        val verification = wsseService.verify(sampleSoap, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe false
        verification.signers shouldHaveSize 0
    }
})
