package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.TestResources
import kz.ncanode.ades.CadesAttributes
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.ades.PadesInspector
import kz.ncanode.dto.request.PadesSignBatchRequest
import kz.ncanode.dto.request.PadesSignRequest
import kz.ncanode.dto.request.PadesVerifyBatchRequest
import kz.ncanode.dto.request.PadesVerifyRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.wrapper.KalkanWrapper
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getTspHashAlgorithmByOid
import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSFloat
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.cos.COSStream
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.common.PDStream
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquareCircle
import org.apache.pdfbox.pdmodel.font.PDType1Font
import org.apache.pdfbox.pdmodel.font.Standard14Fonts
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.util.Calendar
import java.util.Base64

/**
 * PAdES по ETSI EN 319 142-1: уровни B, T, LT и LTA.
 *
 * Состав CMS сверен с реализацией НУЦ (`PadesSignatureService` из NCALayer) —
 * в PDF профиль требует иного набора атрибутов, чем в CAdES: только привязка
 * к сертификату, без `signingTime` (его несёт запись `/M` словаря подписи) и
 * без `cmsAlgorithmProtection`. Тест проверяет и присутствие нужного, и
 * отсутствие лишнего: «похожая» подпись с чужими атрибутами не является
 * совместимой.
 */
@SpringBootTest
@ActiveProfiles("test")
class PadesServiceIntegrationTest(
    @param:Autowired private val padesService: PadesService,
    @param:Autowired private val pdfService: PdfService,
) : FunSpec({

    val provider = KalkanProvider()
    val kalkanWrapper = KalkanWrapper(provider)

    val signerCertificate = kalkanWrapper.read(
        TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
    ).certificate.x509Certificate

    fun signerOf(p12: String = "individual_valid.p12") = PadesSignRequest.PadesSigner().apply {
        signer = SignerRequest().apply {
            key = TestResources.loadAsBase64("p12/$p12")
            password = TestResources.P12_PASSWORD
        }
        reason = "Тест PAdES"
        location = "Астана"
    }

    /** Минимальный двухстраничный PDF — вторая страница нужна тесту видимой подписи. */
    val unsignedPdf: String by lazy {
        PDDocument().use { document ->
            repeat(2) { index ->
                val page = PDPage()
                document.addPage(page)
                PDPageContentStream(document, page).use { content ->
                    content.beginText()
                    content.setFont(PDType1Font(Standard14Fonts.FontName.HELVETICA), 12f)
                    content.newLineAtOffset(100f, 700f)
                    content.showText("NCANode PAdES test, page ${index + 1}")
                    content.endText()
                }
            }
            val out = ByteArrayOutputStream()
            document.save(out)
            Base64.getEncoder().encodeToString(out.toByteArray())
        }
    }

    fun request(
        level: AdesLevel = AdesLevel.B,
        signers: List<PadesSignRequest.PadesSigner> = listOf(signerOf()),
    ) = PadesSignRequest().apply {
        pdf = unsignedPdf
        this.signers = signers
        this.level = level
    }

    /** Достаёт CMS из первой подписи PDF. */
    fun firstSigner(pdfBase64: String): SignerInformation {
        val bytes = Base64.getDecoder().decode(pdfBase64)
        return Loader.loadPDF(bytes).use { document ->
            val dictionary = document.signatureDictionaries.first()
            val cms = CMSSignedData(dictionary.getContents(bytes))
            cms.signerInfos.signers.first() as SignerInformation
        }
    }

    /** PDF-шаблон видимой подписи с картинкой — как его строит сам PDFBox. */
    fun visibleSignatureTemplate(page: Int): String {
        val image = BufferedImage(120, 40, BufferedImage.TYPE_INT_ARGB)
        image.createGraphics().apply {
            drawString("NCANode", 10, 25)
            dispose()
        }

        return Loader.loadPDF(Base64.getDecoder().decode(unsignedPdf)).use { document ->
            val designer = PDVisibleSignDesigner(document, image, page)
                .xAxis(100f)
                .yAxis(100f)
                .width(120f)
                .height(40f)
            val properties = PDVisibleSigProperties()
                .signerName("NCANode")
                .signerLocation("Астана")
                .signatureReason("Тест видимой подписи")
                .preferredSize(0)
                .page(page)
                .visualSignEnabled(true)
                .setPdVisibleSignature(designer)
            properties.buildSignature()
            Base64.getEncoder().encodeToString(properties.visibleSignature.readBytes())
        }
    }

    test("level B embeds only the signingCertificateV2 attribute") {
        val signed = padesService.sign(request())
        signed.level shouldBe AdesLevel.B

        val attributes = firstSigner(signed.pdf!!).signedAttributes.shouldNotBeNull()

        // Обязательное для CMS на месте.
        attributes.get(CMSAttributes.contentType).shouldNotBeNull()
        attributes.get(CMSAttributes.messageDigest).shouldNotBeNull()
        // Привязка к сертификату — то, ради чего существует уровень B.
        attributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2).shouldNotBeNull()

        // cmsAlgorithmProtection в PDF не кладётся: в отличие от CAdES, НУЦ
        // его здесь не ставит, а цель — совпасть с их выводом.
        attributes.get(DERObjectIdentifier(CadesAttributes.CMS_ALGORITHM_PROTECTION_OID)).shouldBeNull()

        // А signingTime присутствует, хотя мы его не добавляем: генератор
        // Kalkan дописывает его сам, когда ему передают свою таблицу
        // атрибутов. У НУЦ ровно тот же вызов того же генератора, поэтому их
        // подписи содержат его тоже — совместимость важнее пуризма профиля.
        attributes.get(CMSAttributes.signingTime).shouldNotBeNull()
    }

    test("signingCertificateV2 carries the SHA-256 hash of the signer certificate") {
        val signed = padesService.sign(request())
        val attribute = firstSigner(signed.pdf!!).signedAttributes
            .get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
        val signingCertificate = SigningCertificateV2.getInstance(attribute.attrValues.getObjectAt(0))

        val expected = MessageDigest.getInstance("SHA-256").digest(signerCertificate.encoded)
        signingCertificate.certs[0].certHash.contentEquals(expected) shouldBe true
    }

    test("the existing PDF verification accepts a PAdES signature") {
        // Наш verify требует, чтобы подпись покрывала весь файл; PAdES-подпись
        // обязана это условие выполнять.
        val signed = padesService.sign(request())
        val result = pdfService.verify(PdfVerifyRequest().apply { pdf = signed.pdf!! })

        result.valid shouldBe true
        result.signers.single().coversWholeDocument shouldBe true
    }

    test("level T attaches a signature timestamp") {
        val signed = padesService.sign(request(level = AdesLevel.T))
        signed.level shouldBe AdesLevel.T

        val signer = firstSigner(signed.pdf!!)
        signer.unsignedAttributes.shouldNotBeNull()
            .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).shouldNotBeNull()
    }

    test("each signer adds an incremental revision instead of replacing the previous signature") {
        val signed = padesService.sign(
            request(signers = listOf(signerOf(), signerOf("legal_ceo_valid.p12"))),
        )
        val bytes = Base64.getDecoder().decode(signed.pdf!!)

        Loader.loadPDF(bytes).use { document ->
            document.signatureDictionaries.size shouldBe 2
        }
        // Обе подписи проверяются: вторая не разрушила первую.
        pdfService.verify(PdfVerifyRequest().apply { pdf = signed.pdf!! }).valid shouldBe true
    }

    test("visible signature is placed on the requested page") {
        val signer = signerOf().apply {
            visibleSignature = PadesSignRequest.VisibleSignature().apply {
                template = visibleSignatureTemplate(page = 2)
                page = 2
            }
        }
        val signed = padesService.sign(request(signers = listOf(signer)))

        Loader.loadPDF(Base64.getDecoder().decode(signed.pdf!!)).use { document ->
            val widgets = document.getPage(1).annotations
            // Видимая подпись — это виджет с ненулевым прямоугольником на странице.
            widgets.any { it.rectangle != null && it.rectangle.width > 0 } shouldBe true
            document.getPage(0).annotations.none { it.rectangle != null && it.rectangle.width > 0 } shouldBe true
        }

        pdfService.verify(PdfVerifyRequest().apply { pdf = signed.pdf!! }).valid shouldBe true
    }

    test("a visible signature page beyond the document is refused") {
        val signer = signerOf().apply {
            visibleSignature = PadesSignRequest.VisibleSignature().apply {
                template = visibleSignatureTemplate(page = 1)
                page = 99
            }
        }
        shouldThrow<ClientException> { padesService.sign(request(signers = listOf(signer))) }
            .message!! shouldContain "out of range"
    }

    // ---- проверка ----

    test("verify reports level B and validates it") {
        val signed = padesService.sign(request())
        val result = padesService.verify(PadesVerifyRequest().apply { pdf = signed.pdf!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.B
        result.verifiedLevel shouldBe AdesLevel.B
        result.documentTimestamps shouldBe 0
        result.signatures.single().signer.shouldNotBeNull().coversWholeDocument shouldBe true
    }

    test("verify reports level T for a timestamped signature") {
        val signed = padesService.sign(request(level = AdesLevel.T))
        val result = padesService.verify(PadesVerifyRequest().apply { pdf = signed.pdf!! })

        result.valid shouldBe true
        result.level shouldBe AdesLevel.T
        result.verifiedLevel shouldBe AdesLevel.T
    }

    test("verify rejects a PDF signature bound to another certificate") {
        // Подпись настоящая, но signingCertificateV2 посчитан по чужому
        // сертификату. Без сверки привязки такая подпись прошла бы.
        val foreign = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/legal_ceo_valid.p12"), null, TestResources.P12_PASSWORD,
        ).certificate.x509Certificate
        val keyStore = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )

        val tampered = Loader.loadPDF(Base64.getDecoder().decode(unsignedPdf)).use { document ->
            val signature = PDSignature().apply {
                setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED)
                setSignDate(Calendar.getInstance())
            }
            document.addSignature(
                signature,
                SignatureInterface { content: InputStream ->
                    val certificate = keyStore.certificate.x509Certificate
                    val digestOid = getDigestAlgorithmOidBYSignAlgorithmOid(certificate.sigAlgOID)
                    val generator = CMSSignedDataGenerator()
                    generator.addSigner(
                        keyStore.privateKey,
                        certificate,
                        digestOid,
                        CadesAttributes.padesSignedAttributes(foreign, provider),
                        null as kz.gov.pki.kalkan.asn1.cms.AttributeTable?,
                    )
                    generator.addCertificatesAndCRLs(
                        CertStore.getInstance(
                            "Collection",
                            CollectionCertStoreParameters(listOf(certificate)),
                            KalkanProvider.PROVIDER_NAME,
                        ),
                    )
                    generator.generate(
                        CMSProcessableByteArray(content.readBytes()),
                        false,
                        KalkanProvider.PROVIDER_NAME,
                    ).encoded
                },
            )
            val out = ByteArrayOutputStream()
            document.saveIncremental(out)
            Base64.getEncoder().encodeToString(out.toByteArray())
        }

        padesService.verify(PadesVerifyRequest().apply { pdf = tampered }).valid shouldBe false
    }

    test("revocation material in /DSS for this signer raises the detected level to LT") {
        // В PAdES данные для проверки лежат не в CMS, а в словаре /DSS
        // документа — и уровень поднимается, только если материал относится
        // к этому подписанту (CRL того же издателя либо OCSP про его серийник).
        val signed = padesService.sign(request())
        val withDss = Loader.loadPDF(Base64.getDecoder().decode(signed.pdf!!)).use { document ->
            val stream = COSStream().apply {
                createOutputStream().use { it.write(TestResources.loadBytes("crl/nca_gost2022_test.crl")) }
                isNeedToBeUpdated = true
            }
            val dss = COSDictionary().apply {
                setItem(COSName.getPDFName("CRLs"), COSArray().apply { add(stream) })
                isNeedToBeUpdated = true
            }
            document.documentCatalog.cosObject.apply {
                setItem(COSName.getPDFName("DSS"), dss)
                isNeedToBeUpdated = true
            }
            val out = ByteArrayOutputStream()
            document.saveIncremental(out)
            out.toByteArray()
        }

        PadesInspector.inspect(withDss, provider).single().level shouldBe AdesLevel.LT
    }

    test("a document timestamp is not counted as a signature and does not spoil the verdict") {
        // /DocTimeStamp попадает в общий перебор словарей подписей, но меткой
        // подписанта не является. Здесь метка заведомо негодная — если бы мы
        // считали её подписью, вердикт стал бы отрицательным.
        val signed = padesService.sign(request())
        val withStamp = Loader.loadPDF(Base64.getDecoder().decode(signed.pdf!!)).use { document ->
            val stamp = PDSignature().apply {
                setType(COSName.getPDFName("DocTimeStamp"))
                setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                setSubFilter(COSName.getPDFName("ETSI.RFC3161"))
            }
            document.addSignature(stamp, SignatureInterface { _: InputStream -> ByteArray(64) })
            val out = ByteArrayOutputStream()
            document.saveIncremental(out)
            Base64.getEncoder().encodeToString(out.toByteArray())
        }

        val result = padesService.verify(PadesVerifyRequest().apply { pdf = withStamp })
        result.documentTimestamps shouldBe 1
        result.signatures.size shouldBe 1
        result.level shouldBe AdesLevel.LTA
        // Проверить саму метку мы пока не умеем и честно об этом сообщаем.
        result.verifiedLevel shouldBe AdesLevel.T
    }

    // ---- уровень LT и допустимость инкрементального хвоста ----

    /** Дописывает в подписанный PDF инкрементальное обновление. */
    fun appendRevision(pdfBase64: String, change: (PDDocument) -> Unit): String =
        Loader.loadPDF(Base64.getDecoder().decode(pdfBase64)).use { document ->
            change(document)
            val out = ByteArrayOutputStream()
            document.saveIncremental(out)
            Base64.getEncoder().encodeToString(out.toByteArray())
        }

    test("level LT embeds validation data into /DSS and stays valid") {
        val signed = padesService.sign(request(level = AdesLevel.LT))
        signed.level shouldBe AdesLevel.LT

        Loader.loadPDF(Base64.getDecoder().decode(signed.pdf!!)).use { document ->
            val dss = document.documentCatalog.cosObject
                .getDictionaryObject(COSName.getPDFName("DSS")) as COSDictionary
            (dss.getDictionaryObject(COSName.getPDFName("Certs")) as COSArray).size() shouldBeGreaterThan 1
        }

        // Ключевое: /DSS дописывается ПОСЛЕ подписи, то есть её ByteRange не
        // доходит до конца файла. Такой хвост допустим — он не меняет
        // отображаемое содержимое.
        val result = padesService.verify(PadesVerifyRequest().apply { pdf = signed.pdf!! })
        result.valid shouldBe true
        result.level shouldBe AdesLevel.LT
        result.verifiedLevel shouldBe AdesLevel.T
        result.signatures.single().signer.shouldNotBeNull().coversWholeDocument shouldBe false
    }

    test("a tail that rewrites page content is rejected") {
        // Обратная сторона того же послабления: дописанная ревизия, меняющая
        // видимое содержимое, обязана делать документ недействительным —
        // иначе мы вернулись бы к поведению, при котором подпись ничего не
        // защищает.
        val signed = padesService.sign(request())
        val tampered = appendRevision(signed.pdf!!) { document ->
            val page = document.getPage(0)
            val replacement = PDStream(document)
            replacement.createOutputStream().use {
                it.write("BT /Helv 12 Tf 100 600 Td (ПОДМЕНА) Tj ET".toByteArray())
            }
            page.setContents(replacement)
            page.cosObject.isNeedToBeUpdated = true
        }

        val result = padesService.verify(PadesVerifyRequest().apply { pdf = tampered })
        result.valid shouldBe false
        // Причина отказа — именно покрытие: сама подпись цела и по-прежнему
        // проверяется. Без этой проверки тест мог бы «проходить» из-за того,
        // что подпись сломалась при дописывании ревизии.
        result.signatures.single().signer.shouldNotBeNull().isValid shouldBe true
    }

    test("a tail that adds a visible annotation is rejected") {
        val signed = padesService.sign(request())
        val tampered = appendRevision(signed.pdf!!) { document ->
            val page = document.getPage(0)
            val annotation = COSDictionary().apply {
                setItem(COSName.TYPE, COSName.getPDFName("Annot"))
                setItem(COSName.SUBTYPE, COSName.getPDFName("Square"))
                setItem(
                    COSName.RECT,
                    COSArray().apply {
                        add(COSFloat(100f)); add(COSFloat(100f)); add(COSFloat(200f)); add(COSFloat(150f))
                    },
                )
                isNeedToBeUpdated = true
            }
            val annotations = (page.cosObject.getDictionaryObject(COSName.ANNOTS) as? COSArray)
                ?: COSArray().also { page.cosObject.setItem(COSName.ANNOTS, it) }
            annotations.add(annotation)
            annotations.isNeedToBeUpdated = true
            page.cosObject.isNeedToBeUpdated = true
        }

        val result = padesService.verify(PadesVerifyRequest().apply { pdf = tampered })
        result.valid shouldBe false
        result.signatures.single().signer.shouldNotBeNull().isValid shouldBe true
    }

    test("a tail that adds a catalog entry other than /DSS is rejected") {
        // Содержимое страниц такой хвост не трогает, но меняет поведение
        // документа при открытии — по принятой политике это недопустимо.
        val signed = padesService.sign(request())
        val tampered = appendRevision(signed.pdf!!) { document ->
            document.documentCatalog.cosObject.apply {
                setItem(COSName.getPDFName("OpenAction"), COSDictionary())
                isNeedToBeUpdated = true
            }
        }

        val result = padesService.verify(PadesVerifyRequest().apply { pdf = tampered })
        result.valid shouldBe false
        result.signatures.single().signer.shouldNotBeNull().isValid shouldBe true
    }

    test("level LTA adds a document timestamp that covers the whole file") {
        val signed = padesService.sign(request(level = AdesLevel.LTA))
        signed.level shouldBe AdesLevel.LTA
        val bytes = Base64.getDecoder().decode(signed.pdf!!)

        Loader.loadPDF(bytes).use { document ->
            val dictionaries = document.signatureDictionaries
            dictionaries.size shouldBe 2
            val stamp = dictionaries.last()
            stamp.cosObject.getNameAsString(COSName.TYPE) shouldBe "DocTimeStamp"
            stamp.subFilter shouldBe "ETSI.RFC3161"

            // Метка ставится последней и потому покрывает файл целиком вместе
            // с /DSS — непокрытого хвоста в LTA-документе не остаётся.
            val end = stamp.byteRange.let { it[2] + it[3] }
            end shouldBe bytes.size
        }

        val result = padesService.verify(PadesVerifyRequest().apply { pdf = signed.pdf!! })
        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        result.documentTimestamps shouldBe 1
        result.signatures.size shouldBe 1
    }

    test("the document timestamp really is a timestamp over the covered bytes") {
        // Содержимое /Contents документной метки — сам токен RFC 3161, а не
        // CMS-подпись. Проверяем, что imprint в нём считан по тем байтам,
        // которые метка покрывает.
        val signed = padesService.sign(request(level = AdesLevel.LTA))
        val bytes = Base64.getDecoder().decode(signed.pdf!!)

        Loader.loadPDF(bytes).use { document ->
            val stamp = document.signatureDictionaries.last()
            val token = TimeStampToken(CMSSignedData(stamp.getContents(bytes)))
            val covered = stamp.getSignedContent(bytes)

            val digestOid = getTspHashAlgorithmByOid(signerCertificate.sigAlgOID)
            val expected = MessageDigest.getInstance(digestOid, provider).digest(covered)
            expected.contentEquals(token.timeStampInfo.messageImprintDigest) shouldBe true
        }
    }

    test("levels are reported for a document that is both LT and LTA") {
        // LTA-документ несёт и /DSS, и документную метку: уровень LTA.
        val signed = padesService.sign(request(level = AdesLevel.LTA))
        val result = padesService.verify(PadesVerifyRequest().apply { pdf = signed.pdf!! })
        result.level shouldBe AdesLevel.LTA
        // Отзыв не запрашивали — вшитый материал не смотрели, значит выше T
        // подтверждать нечем.
        result.verifiedLevel shouldBe AdesLevel.T
    }

    // ---- подтверждение уровней LT и LTA по вшитому материалу ----

    test("level LT is confirmed from /DSS, not from the network") {
        // Тот же документ, но проверка отзыва запрошена: вердикт приходит из
        // словаря /DSS, и verifiedLevel поднимается до LT только если вшитые
        // данные оказались авторитетными на момент подписи.
        val signed = padesService.sign(request(level = AdesLevel.LT))
        val result = padesService.verify(
            PadesVerifyRequest().apply {
                pdf = signed.pdf!!
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.verifiedLevel shouldBe AdesLevel.LT
    }

    test("level LTA is confirmed only when the document timestamp checks out") {
        val signed = padesService.sign(request(level = AdesLevel.LTA))
        val result = padesService.verify(
            PadesVerifyRequest().apply {
                pdf = signed.pdf!!
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        result.verifiedLevel shouldBe AdesLevel.LTA
    }

    test("a broken document timestamp does not confirm LTA") {
        // Уровень LTA заявляется самим присутствием /DocTimeStamp, поэтому
        // подтверждать его можно только проверив токен. Затираем его
        // содержимое, не сдвигая ни одного смещения в файле.
        val signed = padesService.sign(request(level = AdesLevel.LTA))
        val bytes = Base64.getDecoder().decode(signed.pdf!!)

        val byteRange = Loader.loadPDF(bytes).use { it.signatureDictionaries.last().byteRange }
        // /Contents — hex-строка в дыре ByteRange, между `<` и `>`.
        val holeStart = byteRange[0] + byteRange[1] + 1
        val holeEnd = byteRange[2] - 1
        val tampered = bytes.copyOf()
        for (index in holeStart until holeEnd) tampered[index] = '0'.code.toByte()

        val result = padesService.verify(
            PadesVerifyRequest().apply {
                pdf = Base64.getEncoder().encodeToString(tampered)
                revocationCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)
            },
        )

        // Сама подпись документа цела — испорчена только метка, поэтому
        // вердикт остаётся положительным, но выше LT уровень не поднимается.
        result.valid shouldBe true
        result.level shouldBe AdesLevel.LTA
        result.verifiedLevel shouldBe AdesLevel.LT
    }

    // ---- batch ----

    test("signBatch signs every document with the shared signer and level") {
        val response = padesService.signBatch(
            PadesSignBatchRequest().apply {
                pdfs = listOf(unsignedPdf, unsignedPdf)
                signers = listOf(signerOf())
                level = AdesLevel.T
            },
        )

        response.status shouldBe 200
        response.results shouldHaveSize 2
        response.results.forEach { item ->
            item.status shouldBe 200
            item.level shouldBe AdesLevel.T
            padesService.verify(
                PadesVerifyRequest().apply { pdf = item.pdf.shouldNotBeNull() },
            ).valid shouldBe true
        }
    }

    test("signBatch keeps going when one document is not a PDF") {
        val response = padesService.signBatch(
            PadesSignBatchRequest().apply {
                pdfs = listOf(unsignedPdf, Base64.getEncoder().encodeToString("не PDF".toByteArray()))
                signers = listOf(signerOf())
            },
        )

        response.results shouldHaveSize 2
        response.results[0].status shouldBe 200
        response.results[1].pdf shouldBe null
    }

    test("verifyBatch verifies each document independently") {
        val signed = padesService.signBatch(
            PadesSignBatchRequest().apply {
                pdfs = listOf(unsignedPdf, unsignedPdf)
                signers = listOf(signerOf())
            },
        )

        val response = padesService.verifyBatch(
            PadesVerifyBatchRequest().apply {
                pdfs = signed.results.map { it.pdf.shouldNotBeNull() }
            },
        )

        response.results shouldHaveSize 2
        response.results.forEach { it.valid shouldBe true }
    }

    test("verifyBatch reports an unsigned document without spoiling the others") {
        val signed = padesService.sign(request()).pdf.shouldNotBeNull()

        val response = padesService.verifyBatch(
            PadesVerifyBatchRequest().apply { pdfs = listOf(signed, unsignedPdf) },
        )

        response.results shouldHaveSize 2
        response.results[0].valid shouldBe true
        response.results[1].valid shouldBe false
        response.results[1].status shouldBe 404
    }
})
