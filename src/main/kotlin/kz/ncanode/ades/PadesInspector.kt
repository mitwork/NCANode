package kz.ncanode.ades

import kz.gov.pki.kalkan.ocsp.BasicOCSPResp
import kz.gov.pki.kalkan.ocsp.OCSPResp
import kz.ncanode.dto.ades.AdesLevel
import org.apache.pdfbox.Loader
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSBase
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.cos.COSStream
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.security.Provider
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

/**
 * Разбор PAdES-специфики: заявленный уровень каждой подписи и привязка к
 * сертификату.
 *
 * В PDF уровни определяются не только содержимым CMS, но и структурами самого
 * документа — по правилам валидатора НУЦ (`PadesSignatureService.validate`):
 *
 *  1. B — базовый;
 *  2. T — в CMS есть `signatureTimeStampToken`;
 *  3. LT — в словаре `/DSS` есть данные об отзыве, **относящиеся именно к
 *     этому подписанту** (а не просто присутствие словаря: в документе с
 *     несколькими подписями материал может покрывать лишь часть из них);
 *  4. LTA — в документе есть документная метка времени (`/DocTimeStamp`).
 *
 * Сами документные метки подписями не являются и помечаются
 * [SignatureFacts.documentTimestamp] — считать их подписантами неверно.
 */
object PadesInspector {

    /** Факты об одном словаре подписи, в порядке обхода PDFBox. */
    data class SignatureFacts(
        val level: AdesLevel,
        /** Это документная метка времени (`/DocTimeStamp`), а не подпись. */
        val documentTimestamp: Boolean,
        /** Сошлась ли привязка `signingCertificateV2`. `true`, если атрибута нет. */
        val signingCertificateMatches: Boolean,
    )

    private val DSS = COSName.getPDFName("DSS")
    private val CRLS = COSName.getPDFName("CRLs")
    private val OCSPS = COSName.getPDFName("OCSPs")
    private val DOC_TIME_STAMP = COSName.getPDFName("DocTimeStamp")

    /**
     * Разбирает документ. Порядок совпадает с
     * [kz.ncanode.service.PdfService.verify] — оба идут по
     * `document.signatureDictionaries`.
     */
    fun inspect(pdfBytes: ByteArray, provider: Provider): List<SignatureFacts> =
        Loader.loadPDF(pdfBytes).use { document ->
            val crls = dssCrls(document)
            val ocspSerials = dssOcspSerials(document)
            val dictionaries = document.signatureDictionaries
            val hasDocumentTimestamp = dictionaries.any { isDocumentTimestamp(it) }

            dictionaries.map { dictionary ->
                if (isDocumentTimestamp(dictionary)) {
                    SignatureFacts(AdesLevel.LTA, documentTimestamp = true, signingCertificateMatches = true)
                } else {
                    signatureFacts(dictionary, pdfBytes, crls, ocspSerials, hasDocumentTimestamp, provider)
                }
            }
        }

    private fun signatureFacts(
        dictionary: PDSignature,
        pdfBytes: ByteArray,
        crls: List<X509CRL>,
        ocspSerials: Set<BigInteger>,
        hasDocumentTimestamp: Boolean,
        provider: Provider,
    ): SignatureFacts {
        val cms = try {
            dictionary.getContents(pdfBytes)
        } catch (e: Exception) {
            log.warn("Cannot read PDF signature contents: {}", e.message)
            return SignatureFacts(AdesLevel.B, documentTimestamp = false, signingCertificateMatches = false)
        }

        // CMS внутри PDF — это CAdES, поэтому наличие метки времени и привязку
        // к сертификату разбираем тем же кодом. Уровни LT и LTA из CMS здесь
        // неприменимы: в PAdES их несут структуры PDF, а не SignedData.
        val cmsFacts = try {
            CadesInspector.inspect(cms, provider).firstOrNull()
        } catch (e: Exception) {
            log.warn("Cannot inspect PDF signature CMS: {}", e.message)
            null
        }

        var level = if (cmsFacts != null && cmsFacts.level.isAtLeast(AdesLevel.T)) AdesLevel.T else AdesLevel.B
        if (revocationApplies(cms, crls, ocspSerials, provider)) {
            level = AdesLevel.LT
        }
        if (hasDocumentTimestamp) {
            level = AdesLevel.LTA
        }

        return SignatureFacts(
            level = level,
            documentTimestamp = false,
            signingCertificateMatches = cmsFacts?.signingCertificateMatches ?: false,
        )
    }

    /**
     * Относится ли материал из `/DSS` к подписанту этой подписи: CRL того же
     * издателя либо OCSP-ответ про его серийный номер.
     */
    private fun revocationApplies(
        cms: ByteArray,
        crls: List<X509CRL>,
        ocspSerials: Set<BigInteger>,
        provider: Provider,
    ): Boolean {
        if (crls.isEmpty() && ocspSerials.isEmpty()) return false
        val certificates = signerCertificates(cms, provider)
        return certificates.any { certificate ->
            certificate.serialNumber in ocspSerials ||
                crls.any { it.issuerX500Principal == certificate.issuerX500Principal }
        }
    }

    private fun signerCertificates(cms: ByteArray, provider: Provider): List<X509Certificate> = try {
        val signedData = kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData(cms)
        val store = signedData.getCertificatesAndCRLs("Collection", provider.name)
        signedData.signerInfos.signers.flatMap { signer ->
            store.getCertificates((signer as kz.gov.pki.kalkan.jce.provider.cms.SignerInformation).sid)
                .filterIsInstance<X509Certificate>()
        }
    } catch (e: Exception) {
        log.warn("Cannot read signer certificates from PDF signature: {}", e.message)
        emptyList()
    }

    /** Материал для проверки из словаря `/DSS`. */
    class EmbeddedMaterial(val crls: List<X509CRL>, val ocspResponses: List<ByteArray>)

    /**
     * Достаёт материал из `/DSS`. Только достаёт: подписи CRL и ответов
     * проверяются при вынесении вердикта, доверять содержимому документа
     * нельзя.
     */
    fun embeddedMaterial(pdfBytes: ByteArray): EmbeddedMaterial =
        Loader.loadPDF(pdfBytes).use { document ->
            EmbeddedMaterial(dssCrls(document), dssEntries(document, OCSPS))
        }

    private fun isDocumentTimestamp(dictionary: PDSignature): Boolean =
        DOC_TIME_STAMP.name == dictionary.cosObject.getNameAsString(COSName.TYPE)

    private fun dssCrls(document: PDDocument): List<X509CRL> {
        val factory = CertificateFactory.getInstance("X.509")
        return dssEntries(document, CRLS).mapNotNull { bytes ->
            try {
                factory.generateCRL(bytes.inputStream()) as X509CRL
            } catch (e: Exception) {
                log.warn("Cannot parse /DSS CRL: {}", e.message)
                null
            }
        }
    }

    /** Серийные номера, про которые есть OCSP-ответы в `/DSS`. */
    private fun dssOcspSerials(document: PDDocument): Set<BigInteger> =
        dssEntries(document, OCSPS).flatMapTo(mutableSetOf()) { bytes ->
            try {
                val basic = OCSPResp(bytes).responseObject as? BasicOCSPResp ?: return@flatMapTo emptyList()
                basic.responses.map { it.certID.serialNumber }
            } catch (e: Exception) {
                log.warn("Cannot parse /DSS OCSP response: {}", e.message)
                emptyList()
            }
        }

    private fun dssEntries(document: PDDocument, name: COSName): List<ByteArray> {
        val dss = document.documentCatalog.cosObject.getDictionaryObject(DSS) as? COSDictionary ?: return emptyList()
        val array = dss.getDictionaryObject(name) as? COSArray ?: return emptyList()
        return array.mapNotNull { readStream(it) }
    }

    private fun readStream(base: COSBase?): ByteArray? {
        val stream = base as? COSStream ?: (base as? org.apache.pdfbox.cos.COSObject)?.`object` as? COSStream
        return stream?.createInputStream()?.use { it.readBytes() }
    }

    private val log = LoggerFactory.getLogger(PadesInspector::class.java)
}
