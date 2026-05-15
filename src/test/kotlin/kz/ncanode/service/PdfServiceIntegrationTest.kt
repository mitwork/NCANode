package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.NoSignaturesFoundException
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.font.Standard14Fonts
import org.apache.pdfbox.pdmodel.font.PDType1Font
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.io.ByteArrayOutputStream
import java.util.Base64

@SpringBootTest
@ActiveProfiles("test")
class PdfServiceIntegrationTest(
    @param:Autowired private val pdfService: PdfService,
    @param:Autowired private val caService: CaService,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec { caService.updateCache(true) }

    fun signerOf(p12: String): PdfSignRequest.PdfSigner = PdfSignRequest.PdfSigner().apply {
        reason = "ncanode-test"
        location = "Almaty"
        signer = SignerRequest().apply {
            key = TestResources.loadAsBase64("p12/$p12")
            password = TestResources.P12_PASSWORD
        }
    }

    // Минимальный 1-страничный PDF, base64-encoded.
    val unsignedPdfBase64: String by lazy {
        PDDocument().use { doc ->
            val page = PDPage()
            doc.addPage(page)
            PDPageContentStream(doc, page).use { content ->
                content.beginText()
                content.setFont(PDType1Font(Standard14Fonts.FontName.HELVETICA), 12f)
                content.newLineAtOffset(100f, 700f)
                content.showText("NCANode test document")
                content.endText()
            }
            val baos = ByteArrayOutputStream()
            doc.save(baos)
            Base64.getEncoder().encodeToString(baos.toByteArray())
        }
    }

    test("sign + verify PDF roundtrip without TSP") {
        val signRequest = PdfSignRequest().apply {
            pdf = unsignedPdfBase64
            signers = listOf(signerOf("individual_valid.p12"))
        }
        val signed = pdfService.sign(signRequest)
        signed.pdf.shouldNotBeNull()

        val verifyRequest = PdfVerifyRequest().apply {
            pdf = signed.pdf!!
        }
        val verification = pdfService.verify(verifyRequest)
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
        verification.signers[0].isValid shouldBe true
    }

    test("sign + verify PDF with TSP (CAdES-T) — genTime present in signer info") {
        val signRequest = PdfSignRequest().apply {
            pdf = unsignedPdfBase64
            signers = listOf(signerOf("individual_valid.p12"))
            isWithTsp = true
        }
        val signed = pdfService.sign(signRequest)

        val verification = pdfService.verify(PdfVerifyRequest().apply {
            pdf = signed.pdf!!
        })
        verification.valid shouldBe true
        verification.signers shouldHaveSize 1
        val signer = verification.signers[0]
        signer.isValid shouldBe true
        signer.signDate.shouldNotBeNull()
        // CAdES-T: digestAlgorithm попадает в response (CMS digest OID).
        signer.digestAlgorithm.shouldNotBeNull()
    }

    test("sign with revoked p12 + verify with OCSP → invalid") {
        val signed = pdfService.sign(PdfSignRequest().apply {
            pdf = unsignedPdfBase64
            signers = listOf(signerOf("individual_revoked.p12"))
        })

        val verification = pdfService.verify(PdfVerifyRequest().apply {
            pdf = signed.pdf!!
            revocationCheck = setOf(CertificateRevocation.OCSP)
        })
        verification.valid shouldBe false
    }

    test("verify on unsigned PDF throws NoSignaturesFoundException") {
        val ex = try {
            pdfService.verify(PdfVerifyRequest().apply { pdf = unsignedPdfBase64 })
            null
        } catch (e: NoSignaturesFoundException) {
            e
        }
        ex.shouldNotBeNull()
    }

    test("PdfSignerInfo fields populated: reason/location/contactInfo from request") {
        val signed = pdfService.sign(PdfSignRequest().apply {
            pdf = unsignedPdfBase64
            signers = listOf(signerOf("individual_valid.p12").apply {
                reason = "test-reason"
                location = "test-location"
                contactInfo = "test-contact"
            })
        })

        val verification = pdfService.verify(PdfVerifyRequest().apply {
            pdf = signed.pdf!!
        })
        verification.signers shouldHaveSize 1
        val signer = verification.signers[0]
        signer.reason shouldBe "test-reason"
        signer.location shouldBe "test-location"
        signer.contactInfo shouldBe "test-contact"
    }
})
