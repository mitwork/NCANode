package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.CadesExtendRequest
import kz.ncanode.dto.request.CadesSignRequest
import kz.ncanode.dto.request.CadesVerifyRequest
import kz.ncanode.dto.request.PadesExtendRequest
import kz.ncanode.dto.request.PadesSignRequest
import kz.ncanode.dto.request.PadesVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.XadesExtendRequest
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.exception.ClientException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.font.PDType1Font
import org.apache.pdfbox.pdmodel.font.Standard14Fonts
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * Повышение уровня готовой подписи — `/{cades,xades,pades}/extend`.
 *
 * Сценарий: подписал клиент, а до долгоживущего уровня документ доводит
 * сервер. Ключ для этого не нужен — всё, что добавляют уровни выше B,
 * надстраивается поверх подписи, ничего не подписывая заново.
 */
@SpringBootTest
@ActiveProfiles("test")
class AdesExtendTest(
    @param:Autowired private val cadesService: CadesService,
    @param:Autowired private val xadesService: XadesService,
    @param:Autowired private val padesService: PadesService,
) : FunSpec({

    val fullCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
    val payload = Base64.getEncoder().encodeToString("extend probe".toByteArray())
    val xml = """<?xml version="1.0" encoding="UTF-8"?><document><data>payload</data></document>"""

    /** Минимальный PDF: в ресурсах готового нет, артефакты делаются на месте. */
    val unsignedPdf: String by lazy {
        PDDocument().use { document ->
            val page = PDPage()
            document.addPage(page)
            PDPageContentStream(document, page).use { content ->
                content.beginText()
                content.setFont(PDType1Font(Standard14Fonts.FontName.HELVETICA), 14f)
                content.newLineAtOffset(72f, 720f)
                content.showText("NCANode extend sample")
                content.endText()
            }
            val out = ByteArrayOutputStream()
            document.save(out)
            Base64.getEncoder().encodeToString(out.toByteArray())
        }
    }

    fun signer() = SignerRequest().apply {
        key = TestResources.loadAsBase64("p12/individual_valid.p12")
        password = TestResources.P12_PASSWORD
    }

    // ---- CAdES ----

    test("CAdES: B is extended to LTA without a key and stays valid") {
        val signed = cadesService.sign(
            CadesSignRequest().apply {
                data = payload
                signers = listOf(signer())
                level = AdesLevel.B
            },
        ).cms.shouldNotBeNull()

        val extended = cadesService.extend(
            CadesExtendRequest().apply {
                cms = signed
                level = AdesLevel.LTA
            },
        )
        extended.level shouldBe AdesLevel.LTA

        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = extended.cms.shouldNotBeNull()
                revocationCheck = fullCheck
            },
        )
        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LTA
        // Подписант остался один: extend не подписывает, а надстраивает.
        result.signers.size shouldBe 1
    }

    test("CAdES: the existing timestamp is kept, not replaced") {
        val signed = cadesService.sign(
            CadesSignRequest().apply {
                data = payload
                signers = listOf(signer())
                level = AdesLevel.T
            },
        ).cms.shouldNotBeNull()
        val before = cadesService.verify(CadesVerifyRequest().apply { cms = signed })
            .signers.single().tsp.shouldNotBeNull().genTime

        val extended = cadesService.extend(
            CadesExtendRequest().apply {
                cms = signed
                level = AdesLevel.LT
            },
        ).cms.shouldNotBeNull()

        // Момент существования подписи не должен «переехать»: свидетельствовать
        // о времени, которого мы не наблюдали, нельзя.
        cadesService.verify(CadesVerifyRequest().apply { cms = extended })
            .signers.single().tsp.shouldNotBeNull().genTime shouldBe before
    }

    test("CAdES: detached needs the data, and extends with it") {
        val signed = cadesService.sign(
            CadesSignRequest().apply {
                data = payload
                signers = listOf(signer())
                level = AdesLevel.T
                isDetached = true
            },
        ).cms.shouldNotBeNull()

        shouldThrow<ClientException> {
            cadesService.extend(CadesExtendRequest().apply { cms = signed; level = AdesLevel.LTA })
        }

        val extended = cadesService.extend(
            CadesExtendRequest().apply {
                cms = signed
                data = payload
                level = AdesLevel.LTA
            },
        ).cms.shouldNotBeNull()

        val result = cadesService.verify(
            CadesVerifyRequest().apply {
                cms = extended
                data = payload
                revocationCheck = fullCheck
            },
        )
        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LTA
    }

    test("CAdES: extending to a level already reached is a client error") {
        val signed = cadesService.sign(
            CadesSignRequest().apply {
                data = payload
                signers = listOf(signer())
                level = AdesLevel.T
            },
        ).cms.shouldNotBeNull()

        shouldThrow<ClientException> {
            cadesService.extend(CadesExtendRequest().apply { cms = signed; level = AdesLevel.B })
        }
    }

    // ---- XAdES ----

    test("XAdES: B is extended to LTA and every signature is raised") {
        val signed = xadesService.sign(
            XadesSignRequest().apply {
                this.xml = xml
                this.signers = listOf(signer())
                this.level = AdesLevel.B
            },
        ).xml.shouldNotBeNull()

        val extended = xadesService.extend(
            XadesExtendRequest().apply {
                this.xml = signed
                this.level = AdesLevel.LTA
            },
        ).xml.shouldNotBeNull()

        val result = xadesService.verify(
            XadesVerifyRequest().apply {
                this.xml = extended
                revocationCheck = fullCheck
            },
        )
        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        result.verifiedLevel shouldBe AdesLevel.LTA
        result.signatures.size shouldBe 1
    }

    test("XAdES: an unsigned document has nothing to extend") {
        shouldThrow<Exception> {
            xadesService.extend(XadesExtendRequest().apply { this.xml = xml; level = AdesLevel.T })
        }
    }

    // ---- PAdES ----

    test("PAdES: T is extended to LTA by adding revisions") {
        val signed = padesService.sign(
            PadesSignRequest().apply {
                this.pdf = unsignedPdf
                this.signers = listOf(
                    PadesSignRequest.PadesSigner().apply { this.signer = signer() },
                )
                this.level = AdesLevel.T
            },
        ).pdf.shouldNotBeNull()

        val extended = padesService.extend(
            PadesExtendRequest().apply {
                this.pdf = signed
                this.level = AdesLevel.LTA
            },
        ).pdf.shouldNotBeNull()

        val result = padesService.verify(
            PadesVerifyRequest().apply {
                this.pdf = extended
                revocationCheck = fullCheck
            },
        )
        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        result.verifiedLevel shouldBe AdesLevel.LTA
        result.documentTimestamps shouldBe 1
        result.signatures.size shouldBe 1
    }

    test("PAdES: level T cannot be added after signing") {
        // Метка подписи лежит внутри самой подписи, в области фиксированного
        // размера: добрать её потом — значит переподписать документ.
        val signed = padesService.sign(
            PadesSignRequest().apply {
                this.pdf = unsignedPdf
                this.signers = listOf(
                    PadesSignRequest.PadesSigner().apply { this.signer = signer() },
                )
                this.level = AdesLevel.B
            },
        ).pdf.shouldNotBeNull()

        shouldThrow<ClientException> {
            padesService.extend(PadesExtendRequest().apply { this.pdf = signed; level = AdesLevel.T })
        }
    }
})
