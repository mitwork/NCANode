package kz.ncanode.ades

import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSBase
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.cos.COSStream
import org.apache.pdfbox.pdmodel.PDDocument
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

/**
 * Словарь `/DSS` (Document Security Store) — способ хранения данных для
 * проверки в PAdES-LT (ETSI EN 319 142-1, ISO 32000-2).
 *
 * В PDF материал лежит не в CMS, а в самом документе: цепочки в `/Certs`,
 * списки отзыва в `/CRLs`, ответы респондера в `/OCSPs`. Поэтому уровень LT
 * здесь добавляется инкрементальным обновлением файла — подпись при этом не
 * трогается и остаётся валидной.
 *
 * `/VRI` (индекс материала по каждой подписи) пока не пишется: он
 * вспомогательный, а `/DSS` с самими данными достаточен и для нашей проверки,
 * и для распознавания уровня.
 */
object PdfDocumentSecurityStore {

    private val DSS = COSName.getPDFName("DSS")
    private val CERTS = COSName.getPDFName("Certs")
    private val CRLS = COSName.getPDFName("CRLs")
    private val OCSPS = COSName.getPDFName("OCSPs")

    /**
     * Добавляет `/DSS` в каталог документа.
     *
     * Уже существующий словарь дополняется, а не заменяется: в документе с
     * несколькими подписями материал накапливается, и затирать чужой означало
     * бы понизить уровень ранее наложенных подписей.
     */
    fun add(
        document: PDDocument,
        certificates: List<X509Certificate>,
        crls: List<X509CRL>,
        ocspResponses: List<ByteArray>,
    ) {
        val catalog = document.documentCatalog.cosObject
        val dss = (catalog.getDictionaryObject(DSS) as? COSDictionary) ?: COSDictionary().also {
            it.setItem(COSName.TYPE, DSS)
        }

        appendStreams(document, dss, CERTS, certificates.map { it.encoded })
        appendStreams(document, dss, CRLS, crls.map { it.encoded })
        appendStreams(document, dss, OCSPS, ocspResponses)

        dss.isNeedToBeUpdated = true
        catalog.setItem(DSS, dss)
        catalog.isNeedToBeUpdated = true
    }

    private fun appendStreams(document: PDDocument, dss: COSDictionary, name: COSName, entries: List<ByteArray>) {
        if (entries.isEmpty()) return

        val array = (dss.getDictionaryObject(name) as? COSArray) ?: COSArray()
        for (entry in entries) {
            array.add(stream(document, entry))
        }
        array.isNeedToBeUpdated = true
        dss.setItem(name, array)
    }

    private fun stream(document: PDDocument, bytes: ByteArray): COSBase =
        document.document.createCOSStream().apply {
            createOutputStream().use { it.write(bytes) }
            isNeedToBeUpdated = true
        }
}
