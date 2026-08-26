package kz.ncanode.ades

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector
import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.ASN1Sequence
import kz.gov.pki.kalkan.asn1.ASN1TaggedObject
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.DERSequence
import kz.gov.pki.kalkan.asn1.DERSet
import kz.gov.pki.kalkan.asn1.DERTaggedObject
import kz.gov.pki.kalkan.asn1.cms.ContentInfo
import kz.gov.pki.kalkan.asn1.cms.SignedData
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import org.slf4j.LoggerFactory
import java.security.cert.CertStore
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

/**
 * Встраивание данных для проверки в CMS — уровень CAdES-LT
 * (ETSI EN 319 122-1).
 *
 * Важно, что материал кладётся **не** в устаревшие атрибуты
 * `id-aa-ets-certValues` / `id-aa-ets-revocationValues`, а в сам `SignedData`:
 * цепочка в поле `certificates`, CRL'и и OCSP-ответы в поле `crls`. Именно так
 * делает NCALayer, и подпись, собранная «по старому профилю», их валидатором
 * как LT распознана не будет.
 *
 * OCSP-ответы не помещаются в `crls` напрямую — они заворачиваются в
 * `[1] OtherRevocationInfoFormat` (RFC 5652 §10.2.1) с OID
 * `id-ri-ocsp-response`.
 */
object CmsValidationData {

    private val log = LoggerFactory.getLogger(CmsValidationData::class.java)

    /** id-ri-ocsp-response. */
    private val OCSP_RESPONSE = DERObjectIdentifier("1.3.6.1.5.5.7.16.2")

    /**
     * Возвращает копию [cms] со встроенными цепочкой и данными об отзыве.
     *
     * Уже присутствующие в подписи сертификаты и CRL сохраняются: подпись
     * могла нести их с самого начала, и терять их при повышении уровня нельзя.
     */
    fun embed(
        cms: CMSSignedData,
        certificates: List<X509Certificate>,
        crls: List<X509CRL>,
        ocspResponses: List<ByteArray>,
    ): CMSSignedData {
        val existing = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
        val material = mutableListOf<Any>()
        material.addAll(existing.getCertificates(null))
        material.addAll(existing.getCRLs(null))
        material.addAll(certificates)
        material.addAll(crls)

        val withCertificates = CMSSignedData.replaceCertificatesAndCRLs(
            cms,
            CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(material.distinct()),
                KalkanProvider.PROVIDER_NAME,
            ),
        )

        return if (ocspResponses.isEmpty()) withCertificates else addOcspResponses(withCertificates, ocspResponses)
    }

    /** Материал для проверки, извлечённый из подписи. */
    class Embedded(val crls: List<X509CRL>, val ocspResponses: List<ByteArray>)

    /**
     * Достаёт из `SignedData.crls` то, что туда положил уровень LT: списки
     * отзыва и OCSP-ответы (последние лежат в `[1] OtherRevocationInfoFormat`).
     *
     * Разбор только достаёт байты; доверять им нельзя — подписи CRL и ответов
     * проверяются при вынесении вердикта (`CrlService.statusOf`,
     * `OcspService.statusOf`).
     */
    fun extract(cmsBytes: ByteArray): Embedded {
        val signedData = SignedData.getInstance(
            ContentInfo.getInstance(ASN1Object.fromByteArray(cmsBytes)).content,
        )
        val revocationInfo = signedData.getCRLs() ?: return Embedded(emptyList(), emptyList())

        val factory = CertificateFactory.getInstance("X.509")
        val crls = mutableListOf<X509CRL>()
        val ocspResponses = mutableListOf<ByteArray>()

        for (index in 0 until revocationInfo.size()) {
            val entry = revocationInfo.getObjectAt(index).getDERObject()
            if (entry is ASN1TaggedObject && entry.tagNo == 1) {
                otherRevocationInfo(entry)?.let { ocspResponses.add(it) }
            } else {
                try {
                    crls.add(factory.generateCRL(entry.getDEREncoded().inputStream()) as X509CRL)
                } catch (e: Exception) {
                    log.warn("Cannot read an embedded CRL: {}", e.message)
                }
            }
        }
        return Embedded(crls, ocspResponses)
    }

    /** `OtherRevocationInfoFormat ::= SEQUENCE { format OID, info ANY }`. */
    private fun otherRevocationInfo(entry: ASN1TaggedObject): ByteArray? = try {
        val sequence = ASN1Sequence.getInstance(entry, false)
        val format = sequence.getObjectAt(0) as DERObjectIdentifier
        if (format == OCSP_RESPONSE) sequence.getObjectAt(1).getDERObject().getDEREncoded() else null
    } catch (e: Exception) {
        log.warn("Cannot read embedded revocation info: {}", e.message)
        null
    }

    /**
     * Дописывает OCSP-ответы в `SignedData.crls`.
     *
     * Штатного API для `OtherRevocationInfoFormat` в CMS-обвязке нет, поэтому
     * структура пересобирается на уровне ASN.1: остальные поля `SignedData`
     * переносятся как есть, меняется только множество `crls`.
     */
    private fun addOcspResponses(cms: CMSSignedData, ocspResponses: List<ByteArray>): CMSSignedData {
        val contentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(cms.encoded))
        val signedData = SignedData.getInstance(contentInfo.content)

        val revocationInfo = ASN1EncodableVector()
        signedData.getCRLs()?.let { existing ->
            for (index in 0 until existing.size()) {
                revocationInfo.add(existing.getObjectAt(index))
            }
        }
        for (response in ocspResponses) {
            val other = ASN1EncodableVector()
            other.add(OCSP_RESPONSE)
            other.add(ASN1Object.fromByteArray(response))
            revocationInfo.add(DERTaggedObject(false, 1, DERSequence(other)))
        }

        val updated = SignedData(
            signedData.digestAlgorithms,
            signedData.encapContentInfo,
            signedData.certificates,
            DERSet(revocationInfo),
            signedData.signerInfos,
        )
        return CMSSignedData(ContentInfo(contentInfo.contentType, updated).getDEREncoded())
    }
}
