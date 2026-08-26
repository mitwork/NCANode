package kz.ncanode.ades

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.DERSequence
import kz.gov.pki.kalkan.asn1.DERSet
import kz.gov.pki.kalkan.asn1.DERTaggedObject
import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.cms.AttributeTable
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes
import kz.gov.pki.kalkan.asn1.ess.ESSCertIDv2
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier
import kz.gov.pki.kalkan.asn1.x509.Time
import java.security.MessageDigest
import java.security.Provider
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Hashtable

/**
 * Подписанные атрибуты уровня CAdES-B (ETSI EN 319 122-1).
 *
 * Состав и способ построения сверены с реализацией НУЦ
 * (`kz.gov.pki.ades.service.CadesSignatureService` из NCALayer) — это не
 * вольная трактовка стандарта, а совместимость с тем, что выдаёт и принимает
 * официальный клиент:
 *
 *  - **`signingCertificateV2`** (RFC 5035) — хэш сертификата подписанта.
 *    Хэш **всегда SHA-256**, в том числе для GOST-сертификатов, а поле
 *    `hashAlgorithm` не заполняется: по RFC 5035 отсутствие означает SHA-256.
 *    `IssuerSerial` не кладётся, массив всегда из одного элемента.
 *  - **`cmsAlgorithmProtection`** (RFC 6211) — фиксирует пару алгоритмов
 *    (дайджест + подпись) внутри подписанных данных, чтобы их нельзя было
 *    подменить в незащищённой части SignerInfo.
 *  - **`signingTime`** — заявленное подписантом время. Само по себе доверия
 *    не несёт (его ставит клиент), доказательством времени служит метка
 *    уровня T.
 *
 * `contentType` и `messageDigest` здесь не перечисляются: их обязан добавить
 * генератор CMS, и тест это проверяет.
 */
object CadesAttributes {

    /** id-aa-CMSAlgorithmProtection, RFC 6211 §2. */
    private val CMS_ALGORITHM_PROTECTION = DERObjectIdentifier("1.2.840.113549.1.9.52")

    /**
     * Собирает подписанные атрибуты уровня B для [certificate].
     *
     * @param digestAlgorithmOid OID алгоритма хэширования, которым
     *   подписывается CMS (он же попадает в `cmsAlgorithmProtection`)
     * @param provider провайдер для вычисления SHA-256 хэша сертификата
     * @param signingTime заявленное время подписи
     */
    fun signedAttributes(
        certificate: X509Certificate,
        digestAlgorithmOid: String,
        provider: Provider,
        signingTime: Date = Date(),
    ): AttributeTable {
        val attributes = Hashtable<DERObjectIdentifier, Attribute>()

        val signingCertificate = signingCertificateV2(certificate, provider)
        attributes[signingCertificate.attrType] = signingCertificate

        val algorithmProtection = algorithmProtection(digestAlgorithmOid, certificate.sigAlgOID)
        attributes[algorithmProtection.attrType] = algorithmProtection

        val signingTimeAttribute = Attribute(CMSAttributes.signingTime, DERSet(Time(signingTime)))
        attributes[signingTimeAttribute.attrType] = signingTimeAttribute

        return AttributeTable(attributes)
    }

    /**
     * Атрибуты для CMS внутри PDF (PAdES, ETSI EN 319 142-1): **только**
     * привязка к сертификату.
     *
     * `signingTime` здесь не кладётся намеренно — время подписи в PDF несёт
     * запись `/M` словаря подписи, и дублировать его в CMS профиль не велит.
     * `cmsAlgorithmProtection` НУЦ в PDF тоже не ставит, а цель этого кода —
     * совпасть с их выводом, а не быть строже.
     */
    fun padesSignedAttributes(certificate: X509Certificate, provider: Provider): AttributeTable {
        val attributes = Hashtable<DERObjectIdentifier, Attribute>()
        val signingCertificate = signingCertificateV2(certificate, provider)
        attributes[signingCertificate.attrType] = signingCertificate
        return AttributeTable(attributes)
    }

    private fun signingCertificateV2(certificate: X509Certificate, provider: Provider): Attribute {
        val certificateHash = MessageDigest.getInstance(SIGNING_CERTIFICATE_DIGEST, provider)
            .digest(certificate.encoded)
        // Первый аргумент — hashAlgorithm; null означает SHA-256 по умолчанию
        // (RFC 5035 §4). Именно так его оставляет реализация НУЦ.
        val certificateId = ESSCertIDv2(null as AlgorithmIdentifier?, certificateHash)
        return Attribute(
            PKCSObjectIdentifiers.id_aa_signingCertificateV2,
            DERSet(SigningCertificateV2(arrayOf(certificateId))),
        )
    }

    /**
     * `CMSAlgorithmProtection ::= SEQUENCE {
     *      digestAlgorithm DigestAlgorithmIdentifier,
     *      signatureAlgorithm [1] SignatureAlgorithmIdentifier OPTIONAL,
     *      macAlgorithm [2] MessageAuthenticationCodeAlgorithm OPTIONAL }`
     *
     * Подпись помечается implicit-тегом [1]; MAC для подписи неприменим.
     */
    private fun algorithmProtection(digestAlgorithmOid: String, signatureAlgorithmOid: String): Attribute {
        val protection = ASN1EncodableVector()
        protection.add(AlgorithmIdentifier(DERObjectIdentifier(digestAlgorithmOid)))
        protection.add(DERTaggedObject(false, 1, AlgorithmIdentifier(DERObjectIdentifier(signatureAlgorithmOid))))
        return Attribute(CMS_ALGORITHM_PROTECTION, DERSet(DERSequence(protection)))
    }

    /**
     * Алгоритм хэша сертификата в `signingCertificateV2`. Не зависит от
     * алгоритма подписи: НУЦ считает SHA-256 и для GOST-ключей.
     */
    const val SIGNING_CERTIFICATE_DIGEST = "SHA-256"

    /** OID атрибута `cmsAlgorithmProtection` — нужен тестам и разбору. */
    const val CMS_ALGORITHM_PROTECTION_OID = "1.2.840.113549.1.9.52"
}
