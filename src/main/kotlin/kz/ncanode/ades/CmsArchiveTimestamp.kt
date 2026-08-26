package kz.ncanode.ades

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector
import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.ASN1Sequence
import kz.gov.pki.kalkan.asn1.ASN1Set
import kz.gov.pki.kalkan.asn1.ASN1TaggedObject
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.DEROctetString
import kz.gov.pki.kalkan.asn1.DERSequence
import kz.gov.pki.kalkan.asn1.DERSet
import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.cms.AttributeTable
import kz.gov.pki.kalkan.asn1.cms.ContentInfo
import kz.gov.pki.kalkan.asn1.cms.SignedData
import kz.gov.pki.kalkan.asn1.cms.SignerInfo
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.exception.ServerException
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.Provider

/**
 * Архивная метка времени CAdES — уровень LTA (ETSI EN 319 122-1 §5.5.3).
 *
 * Смысл уровня: метка накрывает подпись **вместе со всем вшитым материалом**
 * (цепочками, данными об отзыве, предыдущими метками), фиксируя, что всё это
 * существовало в таком виде до момента genTime. Так подпись переживает
 * устаревание алгоритмов: даже когда исходный алгоритм ослабнет, останется
 * доказательство, что подпись была создана и проверена раньше.
 *
 * Используется современный профиль — `archive-timestamp-v3` (`0.4.0.1733.2.4`)
 * с индексом `ATSHashIndex-v3` (`0.4.0.19122.1.5`), тот же, что выпускает
 * NCALayer. Устаревшие `archive-timestamp` v1/v2 из TS 101 733 мы распознаём
 * при проверке, но не выпускаем.
 *
 * Индекс перечисляет хэши того, что метка накрывает косвенно: сертификатов,
 * записей об отзыве и значений неподписанных атрибутов. Без него нельзя было
 * бы понять, какие именно элементы были на месте в момент проставления метки.
 */
object CmsArchiveTimestamp {

    /** id-aa-ets-archiveTimestampV3. */
    val ARCHIVE_TIMESTAMP_V3 = DERObjectIdentifier("0.4.0.1733.2.4")

    /** id-aa-ATSHashIndex-v3. Нужен и при проверке — индекс достают из метки. */
    val ATS_HASH_INDEX_V3 = DERObjectIdentifier("0.4.0.19122.1.5")

    /**
     * `ATSHashIndex-v3 ::= SEQUENCE {
     *      hashIndAlgorithm            AlgorithmIdentifier,
     *      certificatesHashIndex       SEQUENCE OF OCTET STRING,
     *      crlsHashIndex               SEQUENCE OF OCTET STRING,
     *      unsignedAttrValuesHashIndex SEQUENCE OF OCTET STRING }`
     */
    fun hashIndex(
        cms: CMSSignedData,
        signer: SignerInformation,
        digestOid: String,
        provider: Provider,
    ): Attribute {
        val signedData = signedDataOf(cms)
        val digest = digester(digestOid, provider)

        val index = ASN1EncodableVector()
        index.add(AlgorithmIdentifier(DERObjectIdentifier(digestOid)))
        index.add(DERSequence(hashesOf(signedData.certificates, digest)))
        index.add(DERSequence(hashesOf(signedData.getCRLs(), digest)))
        index.add(DERSequence(unsignedAttributeHashes(signer, digest)))

        return Attribute(ATS_HASH_INDEX_V3, DERSet(DERSequence(index)))
    }

    /**
     * Данные, по которым считается imprint метки: тип содержимого, хэш самого
     * содержимого, поля `SignerInfo` **кроме неподписанных атрибутов** и
     * значение индекса.
     *
     * Неподписанные атрибуты исключаются намеренно — именно в них попадёт сама
     * эта метка, и включение их сделало бы расчёт рекурсивным.
     */
    fun imprintInput(
        cms: CMSSignedData,
        signer: SignerInformation,
        digestOid: String,
        hashIndex: Attribute,
        provider: Provider,
    ): ByteArray {
        val signedData = signedDataOf(cms)
        val digest = digester(digestOid, provider)
        val out = ByteArrayOutputStream()

        out.write(signedData.encapContentInfo.contentType.getDEREncoded())

        val content = cms.signedContent?.content as? ByteArray ?: ByteArray(0)
        out.write(digest(content))

        val signerInfo = rawSignerInfo(signedData, signer)
        for (index in 0 until signerInfo.size()) {
            val element = signerInfo.getObjectAt(index).getDERObject()
            // [1] — unsignedAttrs; всё остальное (версия, sid, алгоритмы,
            // подписанные атрибуты, значение подписи) входит в расчёт.
            if (element is ASN1TaggedObject && element.tagNo == 1) continue
            out.write(element.getDEREncoded())
        }

        out.write(hashIndex.attrValues.getObjectAt(0).getDERObject().getDEREncoded())
        return out.toByteArray()
    }

    /**
     * Кладёт индекс внутрь самой метки: по профилю он живёт в неподписанных
     * атрибутах токена, а не рядом с ним.
     */
    fun embedHashIndex(token: TimeStampToken, hashIndex: Attribute): TimeStampToken {
        val tst = CMSSignedData(token.encoded)
        val tstSigner = tst.signerInfos.signers.firstOrNull() as? SignerInformation
            ?: throw ServerException("Timestamp token has no signers")

        val attributes = tstSigner.unsignedAttributes?.toASN1EncodableVector() ?: ASN1EncodableVector()
        attributes.add(hashIndex)
        val updated = SignerInformation.replaceUnsignedAttributes(tstSigner, AttributeTable(attributes))

        return TimeStampToken(CMSSignedData.replaceSigners(tst, SignerInformationStore(listOf(updated))))
    }

    /**
     * Добавляет метку отдельным атрибутом. Именно отдельным: архивные метки
     * накапливаются со временем, и новая не должна вытеснять предыдущую.
     */
    fun attach(signer: SignerInformation, token: TimeStampToken): SignerInformation {
        val attributes = signer.unsignedAttributes?.toASN1EncodableVector() ?: ASN1EncodableVector()
        attributes.add(Attribute(ARCHIVE_TIMESTAMP_V3, DERSet(ASN1Object.fromByteArray(token.encoded))))
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(attributes))
    }

    private fun signedDataOf(cms: CMSSignedData): SignedData =
        SignedData.getInstance(ContentInfo.getInstance(ASN1Object.fromByteArray(cms.encoded)).content)

    private fun digester(digestOid: String, provider: Provider): (ByteArray) -> ByteArray =
        { bytes -> MessageDigest.getInstance(digestOid, provider).digest(bytes) }

    private fun hashesOf(set: ASN1Set?, digest: (ByteArray) -> ByteArray): ASN1EncodableVector {
        val hashes = ASN1EncodableVector()
        if (set == null) return hashes
        for (index in 0 until set.size()) {
            hashes.add(DEROctetString(digest(set.getObjectAt(index).getDERObject().getDEREncoded())))
        }
        return hashes
    }

    /** Хэш каждого значения: DER типа атрибута, слитый с DER самого значения. */
    private fun unsignedAttributeHashes(
        signer: SignerInformation,
        digest: (ByteArray) -> ByteArray,
    ): ASN1EncodableVector {
        val hashes = ASN1EncodableVector()
        val unsigned = signer.unsignedAttributes ?: return hashes

        val attributes = unsigned.toASN1EncodableVector()
        for (index in 0 until attributes.size()) {
            val attribute = Attribute.getInstance(attributes.get(index))
            val type = attribute.attrType.getDERObject().getDEREncoded()
            for (valueIndex in 0 until attribute.attrValues.size()) {
                val value = attribute.attrValues.getObjectAt(valueIndex).getDERObject().getDEREncoded()
                hashes.add(DEROctetString(digest(type + value)))
            }
        }
        return hashes
    }

    /** Исходный `SignerInfo` этого подписанта — по совпадению SID. */
    private fun rawSignerInfo(signedData: SignedData, signer: SignerInformation): ASN1Sequence {
        val wanted = signer.toSignerInfo().sid.getDERObject().getDEREncoded()
        val signerInfos = signedData.signerInfos
        for (index in 0 until signerInfos.size()) {
            val candidate = signerInfos.getObjectAt(index).getDERObject() as ASN1Sequence
            val sid = SignerInfo.getInstance(candidate).sid.getDERObject().getDEREncoded()
            if (sid.contentEquals(wanted)) return candidate
        }
        throw ServerException("SignerInfo not found while building the archive timestamp")
    }
}
