package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.JwsSignRequest
import kz.ncanode.dto.request.JwsSignerRequest
import kz.ncanode.dto.request.JwsVerifyRequest
import kz.ncanode.exception.ClientException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.node.ObjectNode
import java.util.Base64

/**
 * JWS в формате JSON Serialization (RFC 7515 §7.2).
 *
 * Компактная форма вмещает одну подпись, а здесь их может быть несколько — и
 * в отличие от XAdES добавление второй ничего не ломает: каждая подпись
 * покрывает свой заголовок и общий payload, а не документ целиком. Это
 * свойство формата, и тесты его закрепляют.
 */
@SpringBootTest
@ActiveProfiles("test")
class JwsServiceIntegrationTest(
    @param:Autowired private val jwsService: JwsService,
) : FunSpec({

    val mapper = ObjectMapper()

    fun payload(): JsonNode = mapper.readTree("""{"doc":"договор №17","sum":150000}""")

    fun signer(name: String = "individual_valid.p12") = JwsSignerRequest().apply {
        alg = "GG2015"
        key = TestResources.loadAsBase64("p12/$name")
        password = TestResources.P12_PASSWORD
    }

    fun signed(detached: Boolean = false, signers: List<JwsSignerRequest> = listOf(signer())): ObjectNode =
        jwsService.sign(
            JwsSignRequest().apply {
                this.payload = payload()
                this.detached = detached
                this.signers = signers
            },
        ).jws.shouldNotBeNull() as ObjectNode

    test("a signed JWS carries the payload, the signature and the signer certificate") {
        val jws = signed()

        jws.get("payload").shouldNotBeNull()
        val signatures = jws.get("signatures").shouldNotBeNull()
        signatures.size() shouldBe 1

        // Сертификат едет в заголовке x5c — проверяющей стороне не нужно
        // искать его отдельно.
        val header = mapper.readTree(
            Base64.getUrlDecoder().decode(signatures.get(0).get("protected").stringValue()),
        )
        header.get("alg").stringValue() shouldBe "GG2015"
        header.get("x5c").get(0).stringValue().isNotEmpty() shouldBe true
    }

    test("what sign produces, verify accepts") {
        val result = jwsService.verify(
            JwsVerifyRequest().apply {
                jws = signed()
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.signers shouldHaveSize 1
        result.signers.single().certificate.shouldNotBeNull()
        result.payload.shouldNotBeNull().get("doc").stringValue() shouldBe "договор №17"
    }

    test("a second signature does not break the first one") {
        // Ради этого JWS и берут: подписант «вторым по маршруту» дописывает
        // свою подпись рядом, а не переподписывает документ.
        val first = signed()
        val both = jwsService.addSigners(
            JwsSignRequest().apply {
                jws = first
                signers = listOf(signer("legal_ceo_valid.p12"))
            },
        ).jws.shouldNotBeNull() as ObjectNode

        both.get("signatures").size() shouldBe 2

        val result = jwsService.verify(JwsVerifyRequest().apply { jws = both })
        result.valid shouldBe true
        result.signers shouldHaveSize 2
        result.signers.all { it.valid } shouldBe true
    }

    test("a tampered payload invalidates the signature") {
        val jws = signed()
        jws.put("payload", Base64.getUrlEncoder().withoutPadding().encodeToString("""{"doc":"подмена"}""".toByteArray()))

        val result = jwsService.verify(JwsVerifyRequest().apply { this.jws = jws })
        result.valid shouldBe false
        result.signers.single().valid shouldBe false
    }

    test("a detached JWS keeps no payload and needs it back for verification") {
        val jws = signed(detached = true)
        jws.get("payload").shouldBeNull()

        shouldThrow<ClientException> {
            jwsService.verify(JwsVerifyRequest().apply { this.jws = jws })
        }

        val result = jwsService.verify(
            JwsVerifyRequest().apply {
                this.jws = jws
                this.payload = payload()
            },
        )
        result.valid shouldBe true
    }

    test("verification reports each signature separately") {
        // Общий флаг не говорит, чья подпись не сошлась, — поэтому вердикт
        // выдаётся по каждой.
        val both = jwsService.addSigners(
            JwsSignRequest().apply {
                jws = signed()
                signers = listOf(signer("legal_ceo_valid.p12"))
            },
        ).jws.shouldNotBeNull() as ObjectNode

        // Портим подпись второго подписанта.
        val second = both.get("signatures").get(1) as ObjectNode
        val broken = second.get("signature").stringValue().let { "A" + it.substring(1) }
        second.put("signature", broken)

        val result = jwsService.verify(JwsVerifyRequest().apply { jws = both })
        result.valid shouldBe false
        result.signers[0].valid shouldBe true
        result.signers[1].valid shouldBe false
    }

    test("an unsupported algorithm is a client error") {
        shouldThrow<ClientException> {
            jwsService.sign(
                JwsSignRequest().apply {
                    payload = payload()
                    signers = listOf(signer().apply { alg = "HS256" })
                },
            )
        }
    }

    test("signing without a payload is a client error") {
        shouldThrow<ClientException> {
            jwsService.sign(JwsSignRequest().apply { signers = listOf(signer()) })
        }
    }
})
