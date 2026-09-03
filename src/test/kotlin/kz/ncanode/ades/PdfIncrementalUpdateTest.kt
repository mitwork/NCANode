package kz.ncanode.ades

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.common.PDStream
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Разбор инкрементального «хвоста» PDF.
 *
 * Смысл проверки в том, что хвост после подписи бывает и законным
 * (PAdES-LT дописывает `/DSS` именно так), и подделкой: дописать ревизию,
 * которая показывает читателю не то, что подписано, — подпись при этом
 * остаётся валидной. Отличить их можно только по содержимому хвоста, и
 * тесты ниже проходят ровно по этой границе: что мы обязаны принять и что
 * обязаны отвергнуть.
 */
class PdfIncrementalUpdateTest : FunSpec({

    /** Однократно подписанная «ревизия» — база, к которой дописывается хвост. */
    fun basePdf(): ByteArray = PDDocument().use { document ->
        document.addPage(PDPage(PDRectangle.A4))
        ByteArrayOutputStream().also { document.save(it) }.toByteArray()
    }

    /** Дописывает к файлу инкрементальное обновление, не трогая исходные байты. */
    fun increment(base: ByteArray, mutate: (PDDocument) -> Unit): ByteArray =
        Loader.loadPDF(base).use { document ->
            mutate(document)
            ByteArrayOutputStream().also { document.saveIncremental(it) }.toByteArray()
        }

    /** Материал для проверки: то единственное, ради чего хвост и разрешён. */
    fun addDss(document: PDDocument) {
        val dss = COSDictionary()
        val certs = COSArray()
        certs.add(
            document.document.createCOSStream().apply {
                createOutputStream().use { it.write(byteArrayOf(1, 2, 3)) }
                isNeedToBeUpdated = true
            },
        )
        certs.isNeedToBeUpdated = true
        dss.setItem(COSName.getPDFName("Certs"), certs)
        dss.isNeedToBeUpdated = true

        val catalog = document.documentCatalog.cosObject
        catalog.setItem(COSName.getPDFName("DSS"), dss)
        catalog.isNeedToBeUpdated = true
    }

    test("the covered end is the second byte range part, and an unusable range gives nothing") {
        PdfIncrementalUpdate.coveredEnd(intArrayOf(0, 100, 200, 50)) shouldBe 250
        PdfIncrementalUpdate.coveredEnd(null).shouldBeNull()
        PdfIncrementalUpdate.coveredEnd(intArrayOf(0, 100)).shouldBeNull()
    }

    test("a range covering the whole file needs no analysis, a nonsensical one is refused") {
        val pdf = basePdf()

        PdfIncrementalUpdate.addsOnlyValidationMaterial(pdf, pdf.size) shouldBe true
        PdfIncrementalUpdate.addsOnlyValidationMaterial(pdf, 0) shouldBe false
        PdfIncrementalUpdate.addsOnlyValidationMaterial(pdf, pdf.size + 1) shouldBe false
    }

    test("a tail that only adds validation data is accepted") {
        val base = basePdf()
        val extended = increment(base) { addDss(it) }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe true
    }

    test("a tail that adds nothing to verify with is refused") {
        // Дописанные байты, не несущие ни /DSS, ни новой подписи, — это не
        // разрешённое обновление, а просто изменение файла после подписи.
        val base = basePdf()
        val extended = increment(base) { document ->
            document.documentInformation.title = "дописано после подписи"
            document.documentInformation.cosObject.isNeedToBeUpdated = true
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe false
    }

    test("a tail that adds catalog entries beyond the validation store is refused") {
        // /OpenAction содержимое страниц не меняет, но меняет поведение
        // документа при открытии — под видом материала для проверки это не проходит.
        val base = basePdf()
        val extended = increment(base) { document ->
            addDss(document)
            document.documentCatalog.cosObject.setItem(COSName.getPDFName("OpenAction"), COSDictionary())
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe false
    }

    test("a tail that changes what a page shows is refused") {
        val base = basePdf()
        val extended = increment(base) { document ->
            addDss(document)
            val page = document.getPage(0)
            val contents = PDStream(document, ByteArrayInputStream("0 0 100 100 re f".toByteArray()))
            contents.cosObject.isNeedToBeUpdated = true
            page.setContents(contents)
            page.cosObject.isNeedToBeUpdated = true
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe false
    }

    test("a tail that adds a visible annotation is refused") {
        val base = basePdf()
        val extended = increment(base) { document ->
            addDss(document)
            val page = document.getPage(0)
            val note = PDAnnotationLink()
            note.rectangle = PDRectangle(10f, 10f, 200f, 200f)
            note.cosObject.isNeedToBeUpdated = true
            page.annotations = listOf(note)
            page.cosObject.isNeedToBeUpdated = true
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe false
    }

    test("a tail that adds an invisible signature field is accepted") {
        // Так выглядит документная метка времени: новое поле подписи без
        // видимого представления. Читателю оно ничего не показывает.
        val base = basePdf()
        val extended = increment(base) { document ->
            addDss(document)
            val page = document.getPage(0)
            val field = PDAnnotationWidget()
            field.rectangle = PDRectangle(0f, 0f, 0f, 0f)
            field.cosObject.isNeedToBeUpdated = true
            page.annotations = listOf(field)
            page.cosObject.isNeedToBeUpdated = true
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe true
    }

    test("a tail that adds a signature field with a visible area is refused") {
        // Поле подписи с ненулевым прямоугольником рисуется поверх страницы —
        // то есть показывает читателю то, чего в подписанной ревизии не было.
        val base = basePdf()
        val extended = increment(base) { document ->
            addDss(document)
            val page = document.getPage(0)
            val field = PDAnnotationWidget()
            field.rectangle = PDRectangle(10f, 10f, 200f, 100f)
            field.cosObject.isNeedToBeUpdated = true
            page.annotations = listOf(field)
            page.cosObject.isNeedToBeUpdated = true
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe false
    }

    test("a tail that adds a page is refused") {
        val base = basePdf()
        val extended = increment(base) { document ->
            addDss(document)
            document.addPage(PDPage(PDRectangle.A4))
            document.documentCatalog.pages.cosObject.isNeedToBeUpdated = true
            document.documentCatalog.cosObject.isNeedToBeUpdated = true
        }

        PdfIncrementalUpdate.addsOnlyValidationMaterial(extended, base.size) shouldBe false
    }

    test("coverage cannot be established for an unsigned document or for something that is not a PDF") {
        PdfIncrementalUpdate.coverageAcceptable(basePdf()) shouldBe false
        PdfIncrementalUpdate.coverageAcceptable("это не PDF".toByteArray()) shouldBe false
    }
})
