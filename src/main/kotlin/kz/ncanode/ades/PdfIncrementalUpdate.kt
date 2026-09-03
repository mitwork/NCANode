package kz.ncanode.ades

import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget
import org.slf4j.LoggerFactory

/**
 * Анализ инкрементального «хвоста» PDF — того, что дописано в файл после
 * последней подписи.
 *
 * Зачем: PAdES-LT по стандарту добавляет данные для проверки (`/DSS`) именно
 * инкрементальным обновлением, то есть подпись законно не покрывает конец
 * файла. Но ровно таким же обновлением делается и подделка: дописать ревизию,
 * подменяющую отображаемое содержимое, оставив подпись валидной
 * (ISO 32000-1 §12.8.1).
 *
 * Отличить одно от другого нельзя по факту наличия хвоста — только по его
 * содержимому. Здесь реализована принятая политика: **хвост допустим, если он
 * добавляет только `/DSS` и невидимые поля подписи**. Всё прочее —
 * изменённые страницы, новые видимые аннотации, новые ключи каталога — делает
 * документ непокрытым, как и раньше.
 *
 * Для сравнения разбираются два документа: файл целиком и его префикс длиной
 * по `/ByteRange` подписи (префикс — это и есть подписанная ревизия, тоже
 * корректный PDF).
 *
 * Замечание: валидатор NCALayer покрытие не проверяет вовсе, поэтому принимает
 * и подделку тоже. Здесь мы намеренно строже.
 */
object PdfIncrementalUpdate {

    private val DSS = COSName.getPDFName("DSS")
    private val CERTS = COSName.getPDFName("Certs")
    private val CRLS = COSName.getPDFName("CRLs")
    private val OCSPS = COSName.getPDFName("OCSPs")

    /**
     * Допустимо ли покрытие документа подписями.
     *
     * Истинно, если какая-то подпись покрывает файл целиком, либо непокрытый
     * хвост добавляет только материал для проверки. Одна реализация на всех,
     * чтобы `/pdf/verify` и `/pades/verify` не разошлись в вердикте по одному
     * и тому же файлу.
     */
    fun coverageAcceptable(pdfBytes: ByteArray): Boolean = try {
        Loader.loadPDF(pdfBytes).use { document ->
            val ends = document.signatureDictionaries.mapNotNull { coveredEnd(it.byteRange) }
            when {
                ends.isEmpty() -> false
                ends.any { it == pdfBytes.size } -> true
                else -> addsOnlyValidationMaterial(pdfBytes, ends.max())
            }
        }
    } catch (e: Exception) {
        log.warn("Cannot inspect PDF signature coverage: {}", e.message)
        false
    }

    /** Конец подписанного диапазона: начало второй части `/ByteRange` плюс её длина. */
    fun coveredEnd(byteRange: IntArray?): Int? {
        if (byteRange == null || byteRange.size < 4) return null
        return byteRange[2] + byteRange[3]
    }

    /**
     * Добавляет ли хвост после [coveredEnd] только материал для проверки.
     *
     * @param coveredEnd конец диапазона `/ByteRange` подписи — граница
     *   подписанной ревизии
     */
    fun addsOnlyValidationMaterial(pdfBytes: ByteArray, coveredEnd: Int): Boolean {
        if (coveredEnd <= 0 || coveredEnd > pdfBytes.size) return false
        if (coveredEnd == pdfBytes.size) return true

        return try {
            Loader.loadPDF(pdfBytes.copyOf(coveredEnd)).use { signed ->
                Loader.loadPDF(pdfBytes).use { current ->
                    // Хвост допустим не потому, что он «ничего не портит», а
                    // потому что он несёт материал для проверки. Дописанные
                    // байты, не добавляющие ни /DSS, ни поля подписи, — это не
                    // разрешённое обновление, а просто мусор в конце файла,
                    // и трактовать его как безобидный нельзя.
                    addsValidationMaterial(signed, current) &&
                        catalogAddsOnlyDss(signed, current) &&
                        pagesUnchanged(signed, current)
                }
            }
        } catch (e: Exception) {
            // Не разобрали — считаем хвост неприемлемым: непрозрачное
            // изменение хуже отсутствия изменений.
            log.warn("Cannot analyse the incremental update: {}", e.message)
            false
        }
    }

    /**
     * Несёт ли хвост то, ради чего он вообще разрешён: появившийся или
     * пополнившийся `/DSS`, либо новое невидимое поле подписи (его добавляет
     * документная метка времени).
     */
    private fun addsValidationMaterial(signed: PDDocument, current: PDDocument): Boolean {
        val before = signed.documentCatalog.cosObject.getDictionaryObject(DSS) as? COSDictionary
        val after = current.documentCatalog.cosObject.getDictionaryObject(DSS) as? COSDictionary

        if (after != null && (before == null || entryCount(after) > entryCount(before))) return true

        // Документная метка времени приходит без /DSS, но добавляет своё
        // (невидимое) поле подписи.
        return current.signatureDictionaries.size > signed.signatureDictionaries.size
    }

    /** Сколько всего записей лежит в `/DSS`. */
    private fun entryCount(dss: COSDictionary): Int =
        listOf(CERTS, CRLS, OCSPS).sumOf { (dss.getDictionaryObject(it) as? COSArray)?.size() ?: 0 }

    /**
     * В каталоге допустимо появление ровно одного нового ключа — `/DSS`.
     * Так отсекаются, например, дописанные `/OpenAction` или `/Names`:
     * содержимое страниц они не меняют, но поведение документа — да.
     */
    private fun catalogAddsOnlyDss(signed: PDDocument, current: PDDocument): Boolean {
        val before = signed.documentCatalog.cosObject.keySet()
        val after = current.documentCatalog.cosObject.keySet()

        val removed = before - after
        if (removed.isNotEmpty()) {
            log.warn("Incremental update removed catalog entries: {}", removed)
            return false
        }
        val added = after - before
        if (added.any { it != DSS }) {
            log.warn("Incremental update added catalog entries beyond /DSS: {}", added - DSS)
            return false
        }
        return true
    }

    /**
     * Страницы должны остаться теми же: их количество, содержимое и набор
     * аннотаций. Появиться может только невидимое поле подписи — его добавляет
     * документная метка времени.
     */
    private fun pagesUnchanged(signed: PDDocument, current: PDDocument): Boolean {
        if (signed.numberOfPages != current.numberOfPages) {
            log.warn(
                "Incremental update changed the page count: {} -> {}",
                signed.numberOfPages, current.numberOfPages,
            )
            return false
        }

        for (index in 0 until signed.numberOfPages) {
            val before = signed.getPage(index)
            val after = current.getPage(index)

            if (!contentEquals(before, after)) {
                log.warn("Incremental update changed the content of page {}", index + 1)
                return false
            }
            if (!annotationsAcceptable(before, after)) {
                log.warn("Incremental update changed the annotations of page {}", index + 1)
                return false
            }
        }
        return true
    }

    private fun contentEquals(before: PDPage, after: PDPage): Boolean {
        val beforeBytes = before.contents?.use { it.readBytes() } ?: ByteArray(0)
        val afterBytes = after.contents?.use { it.readBytes() } ?: ByteArray(0)
        return beforeBytes.contentEquals(afterBytes)
    }

    /**
     * Прежние аннотации должны сохраниться как есть, а добавленные — быть
     * невидимыми полями подписи (нулевой прямоугольник). Видимая аннотация в
     * хвосте — это и есть способ показать читателю не то, что подписано.
     */
    private fun annotationsAcceptable(before: PDPage, after: PDPage): Boolean {
        val existing = before.annotations.map { identity(it) }
        val present = after.annotations.map { identity(it) to it }

        if (!present.map { it.first }.containsAll(existing)) return false

        val added = present.filterNot { it.first in existing }
        return added.all { (_, annotation) -> isInvisibleSignatureField(annotation) }
    }

    private fun identity(annotation: PDAnnotation): String {
        val rectangle = annotation.rectangle
        return listOf(
            annotation.subtype ?: "",
            rectangle?.lowerLeftX, rectangle?.lowerLeftY,
            rectangle?.upperRightX, rectangle?.upperRightY,
            annotation.contents ?: "",
        ).joinToString("|")
    }

    private fun isInvisibleSignatureField(annotation: PDAnnotation): Boolean {
        if (annotation.subtype != PDAnnotationWidget.SUB_TYPE) return false
        val rectangle = annotation.rectangle ?: return true
        return rectangle.width == 0f && rectangle.height == 0f
    }

    private val log = LoggerFactory.getLogger(PdfIncrementalUpdate::class.java)
}
