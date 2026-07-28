package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kz.ncanode.TestResources
import kz.ncanode.dto.request.WsseSignBatchRequest
import kz.ncanode.dto.request.WsseSignRequest
import kz.ncanode.dto.request.WsseVerifyBatchRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

@SpringBootTest
@ActiveProfiles("test")
class WsseServiceIntegrationTest(
    @param:Autowired private val wsseService: WsseService,
    @param:Autowired private val caService: CaService,
) : FunSpec({


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

    // --- Audit fix 2.3: signature must cover the SOAP Body (anti-XSW) ---
    test("verify: signature not bound to the actual SOAP Body → invalid") {
        val signed = wsseService.sign(WsseSignRequest().apply {
            xml = sampleSoap
            key = TestResources.loadAsBase64("p12/individual_valid.p12")
            password = TestResources.P12_PASSWORD
        })
        val signedXml = signed.xml!!

        // Ломаем привязку подписи к Body: меняем wsu:Id на самом Body, оставляя
        // ds:Reference URI прежним. Подпись больше не покрывает настоящий Body.
        val signedId = Regex("""URI="#([^"]+)"""").find(signedXml)!!.groupValues[1]
        val tampered = signedXml.replaceFirst("""wsu:Id="$signedId"""", """wsu:Id="$signedId-moved"""")
        tampered shouldNotBe signedXml

        val verification = wsseService.verify(tampered, checkOcsp = false, checkCrl = false)
        verification.valid shouldBe false
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

    test("signBatch + verifyBatch: roundtrip on N envelopes with one shared key") {
        val signRequest = WsseSignBatchRequest().apply {
            xmls = listOf(sampleSoap, sampleSoap, sampleSoap)
            key = TestResources.loadAsBase64("p12/individual_valid.p12")
            password = TestResources.P12_PASSWORD
        }
        val signed = wsseService.signBatch(signRequest)
        signed.results shouldHaveSize 3
        signed.results.forEach {
            it.status shouldBe 200
            it.xml.shouldNotBeNull()
        }

        val verifyResponse = wsseService.verifyBatch(WsseVerifyBatchRequest().apply {
            xmls = signed.results.map { it.xml!! }
        })
        verifyResponse.results shouldHaveSize 3
        verifyResponse.results.forEach { it.valid shouldBe true }
    }

    test("signBatch: partial response — malformed XML doesn't kill others") {
        val request = WsseSignBatchRequest().apply {
            xmls = listOf(sampleSoap, "<unclosed", sampleSoap)
            key = TestResources.loadAsBase64("p12/individual_valid.p12")
            password = TestResources.P12_PASSWORD
        }
        val response = wsseService.signBatch(request)

        response.results shouldHaveSize 3
        response.results[0].status shouldBe 200
        response.results[0].xml.shouldNotBeNull()
        response.results[1].status shouldBe 500
        response.results[1].xml shouldBe null
        response.results[2].status shouldBe 200
        response.results[2].xml.shouldNotBeNull()
    }
})
