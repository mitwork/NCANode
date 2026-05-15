package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import kz.ncanode.TestResources
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.exception.ClientException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

@SpringBootTest
@ActiveProfiles("test")
class JwtServiceIntegrationTest(
    @param:Autowired private val jwtService: JwtService,
    @param:Autowired private val caService: CaService,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec { caService.updateCache(true) }

    fun encodeRequest(p12: String, payloadClaims: Map<String, Any?>) = JwtEncodeRequest().apply {
        key = TestResources.loadAsBase64("p12/$p12")
        password = TestResources.P12_PASSWORD
        jwt = JwtEncodeRequest.JwtRequest().apply {
            header = JwtEncodeRequest.JwtHeader().apply {
                alg = "GG2015"
                typ = "JWT"
            }
            payload = JwtEncodeRequest.JwtPayload().apply {
                payloadClaims.forEach { (k, v) -> setClaim(k, v) }
            }
        }
    }

    test("encode GG2015 + decode roundtrip — valid signature, payload preserved") {
        val encoded = jwtService.encode(
            encodeRequest("individual_valid.p12", mapOf("sub" to "ncanode-test", "n" to 42))
        )
        encoded.jwt.shouldNotBeNull()
        // JWT — три base64-url-safe сегмента через точку, начинается с header.
        encoded.jwt!! shouldStartWith "eyJ"

        // Извлекаем cert из p12 (через KalkanWrapper побочно — но для decode нам нужен
        // именно cert-base64). Проще: тот же KalkanWrapper читает p12 и отдаёт cert,
        // его кодируем в base64 и передаём в decode.
        val ks = jwtService.javaClass.getDeclaredField("kalkanWrapper").apply { isAccessible = true }
        // Альтернативный путь без reflection — но он короче: используем
        // certBase64 из toCertificateInfo().publicKey? Нет, нужен сам cert PEM/DER.
        // Прямо через KalkanWrapper.read недоступно; берём cert из p12 через
        // встроенный JDK KeyStore — приоритет читаемости.
        val raw = java.io.ByteArrayInputStream(
            java.util.Base64.getDecoder().decode(TestResources.loadAsBase64("p12/individual_valid.p12"))
        )
        val keyStore = java.security.KeyStore.getInstance("PKCS12",
            kz.gov.pki.kalkan.jce.provider.KalkanProvider.PROVIDER_NAME)
        keyStore.load(raw, TestResources.P12_PASSWORD.toCharArray())
        val alias = keyStore.aliases().nextElement()
        val cert = keyStore.getCertificate(alias)
        val certBase64 = java.util.Base64.getEncoder().encodeToString(cert.encoded)

        val decoded = jwtService.decode(JwtDecodeRequest().apply {
            jwt = encoded.jwt!!
            key = certBase64
        })

        decoded.valid shouldBe true
        val jwt = decoded.jwt.shouldNotBeNull()
        jwt.header.shouldNotBeNull()["alg"] shouldBe "GG2015"
        val payload = jwt.payload.shouldNotBeNull()
        payload.containsKey("sub") shouldBe true
        payload["sub"] shouldBe "ncanode-test"
    }

    test("decode with malformed JWT throws ClientException") {
        val ex = try {
            jwtService.decode(JwtDecodeRequest().apply {
                jwt = "not.a.valid.jwt"
                key = java.util.Base64.getEncoder().encodeToString(
                    TestResources.loadBytes("ca/nca_gost2022_test.cer")
                )
            })
            null
        } catch (e: ClientException) {
            e
        }
        ex.shouldNotBeNull()
    }
})
