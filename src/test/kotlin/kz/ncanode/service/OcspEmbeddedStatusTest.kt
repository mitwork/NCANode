package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.util.Date

/**
 * Вердикт по OCSP-ответам, вшитым в подпись (уровень LT).
 *
 * Ответы берутся живые: подделать подписанный OCSP-ответ нельзя, а проверка
 * подписи ответчика — половина смысла этой ветки. Дальше один и тот же ответ
 * оценивается на разные моменты: свежий отвечает и про «сейчас», и про
 * недавнее прошлое, но не про времена до выпуска сертификата.
 */
@SpringBootTest
@ActiveProfiles("test")
class OcspEmbeddedStatusTest(
    @param:Autowired private val ocspService: OcspService,
    @param:Autowired private val caService: CaService,
    @param:Autowired private val kalkanWrapper: KalkanWrapper,
) : FunSpec({

    beforeSpec { caService.updateCache(true) }

    fun certificateOf(name: String) = kalkanWrapper.read(
        TestResources.loadAsBase64("p12/$name"), null, TestResources.P12_PASSWORD,
    ).certificate.apply { issuerCertificate = caService.getRootCertificateFor(this) }

    test("a live response answers about the moment it was issued for") {
        val cert = certificateOf("individual_valid.p12")
        val responses = ocspService.collectResponses(cert, cert.issuerCertificate)
        responses.isNotEmpty() shouldBe true

        val statuses = ocspService.statusOf(cert, cert.issuerCertificate, responses, Date())
        statuses.isNotEmpty() shouldBe true
        statuses.all { it.result == OcspResult.ACTIVE } shouldBe true
    }

    test("a response issued after the certificate expired says nothing about its past") {
        // Граница правила: пока сертификат действовал, более поздний ответ
        // свидетельствует и о прошлом — отзыв необратим и датирован. После
        // истечения запись о нём могут убрать, и «ответ ни о чём» стал бы
        // выглядеть как добропорядочность.
        val expired = certificateOf("expired_individual.p12")
        val responses = ocspService.collectResponses(expired, expired.issuerCertificate)
        responses.isNotEmpty() shouldBe true

        val whileValid = Date(expired.x509Certificate.notAfter.time - 24 * 3_600_000)
        val statuses = ocspService.statusOf(expired, expired.issuerCertificate, responses, whileValid)

        statuses.all { it.result == OcspResult.UNAVAILABLE } shouldBe true
    }

    test("a response about another certificate is not evidence about this one") {
        // Ответ про чужой серийник просто не относится к делу: не UNKNOWN
        // (это был бы отказ доверия), а «данных нет».
        val signer = certificateOf("individual_valid.p12")
        val other = certificateOf("legal_ceo_valid.p12")
        val responses = ocspService.collectResponses(other, other.issuerCertificate)

        ocspService.statusOf(signer, signer.issuerCertificate, responses, Date()).shouldBeEmpty()
    }

    test("unreadable bytes are UNKNOWN: an answer we cannot trust is not an answer") {
        val cert = certificateOf("individual_valid.p12")

        val statuses = ocspService.statusOf(
            cert, cert.issuerCertificate, listOf("не ответ вовсе".toByteArray()), Date(),
        )

        statuses.single().result shouldBe OcspResult.UNKNOWN
    }

    test("without an issuer there is nothing to check the response against") {
        val cert = certificateOf("individual_valid.p12")
        val responses = ocspService.collectResponses(cert, cert.issuerCertificate)

        ocspService.statusOf(cert, null, responses, Date()).shouldBeEmpty()
    }
})
