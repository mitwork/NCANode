package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.SbaSignBatchRequest
import kz.ncanode.dto.request.SbaSignRequest
import kz.ncanode.dto.request.SbaVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

/**
 * Подпись произвольных данных без контейнера (`/x509/sign`).
 *
 * Главное здесь — сходимость пары: то, что подписал `/x509/sign`, обязан
 * принять `/x509/verify`. Обе стороны трактуют данные одинаково — как строку
 * в UTF-8, — и тест с кириллицей это стережёт: при расхождении кодировок
 * ASCII-проверка прошла бы, а первый же не-ASCII символ всё сломал бы.
 */
@SpringBootTest
@ActiveProfiles("test")
class SbaSignIntegrationTest(
    @param:Autowired private val certificateService: CertificateService,
) : FunSpec({

    fun signer(name: String = "individual_valid.p12") = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/$name")
        password = TestResources.P12_PASSWORD
    }

    test("what sign produces, verify accepts") {
        val data = "Данные для подписи, включая кириллицу и символы: №«»"

        val signed = certificateService.sign(
            SbaSignRequest().apply {
                this.data = data
                this.signer = signer()
            },
        )
        signed.signature.shouldNotBeNull()
        signed.certificate.shouldNotBeNull()

        val result = certificateService.verify(
            signed.certificate!!,
            signed.signature!!,
            data,
            checkOcsp = false,
            checkCrl = false,
        )
        result.valid shouldBe true
    }

    test("the returned certificate is the signer's own") {
        // Сертификат отдаётся вместе с подписью именно затем, чтобы
        // проверяющей стороне не искать его отдельно.
        val signed = certificateService.sign(
            SbaSignRequest().apply {
                data = "payload"
                signer = signer()
            },
        )

        val info = certificateService.info(
            listOf(signed.certificate.shouldNotBeNull()),
            checkOcsp = false,
            checkCrl = false,
        )
        info.signers.single().shouldNotBeNull().subject.shouldNotBeNull()
    }

    test("other data does not verify against the signature") {
        val signed = certificateService.sign(
            SbaSignRequest().apply {
                data = "оригинал"
                signer = signer()
            },
        )

        certificateService.verify(
            signed.certificate!!,
            signed.signature!!,
            "подделка",
            checkOcsp = false,
            checkCrl = false,
        ).valid shouldBe false
    }

    test("signing checks the certificate the same way verification does") {
        // Отозванный ключ подписать не мешает — подпись математически верна;
        // непригодным его делает проверка, и она это показывает.
        val signed = certificateService.sign(
            SbaSignRequest().apply {
                data = "payload"
                signer = signer("individual_revoked.p12")
            },
        )

        val result = certificateService.verify(
            signed.certificate!!,
            signed.signature!!,
            "payload",
            checkOcsp = true,
            checkCrl = false,
        )
        result.valid shouldBe false
    }

    test("batch signs every item with the same key") {
        val response = certificateService.signBatch(
            SbaSignBatchRequest().apply {
                data = listOf("первый", "второй", "третий")
                signer = signer()
            },
        )

        response.results shouldHaveSize 3
        response.results.forEach { it.status shouldBe 200 }
        response.results.map { it.signature }.toSet() shouldHaveSize 3
    }

    test("a request without a signer is a client error") {
        shouldThrow<ClientException> {
            certificateService.sign(SbaSignRequest().apply { data = "payload" })
        }
    }
})
