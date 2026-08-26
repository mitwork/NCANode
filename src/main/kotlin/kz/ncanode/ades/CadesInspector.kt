package kz.ncanode.ades

import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.cms.ContentInfo
import kz.gov.pki.kalkan.asn1.cms.SignedData
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.ncanode.dto.ades.AdesLevel
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.Provider
import java.security.cert.X509Certificate

/**
 * Разбор CAdES-специфики подписи: заявленный уровень и привязка подписи к
 * сертификату подписанта.
 *
 * Уровень определяется **наличием элементов, а не их валидностью**: подпись с
 * испорченной меткой времени всё равно заявляет уровень T, просто не проходит
 * проверку. «Что подпись о себе заявляет» и «что мы подтвердили» — разные
 * вопросы, и смешивать их в одном поле нельзя.
 *
 * Правила взяты из валидатора НУЦ (`CadesSignatureService.validateSigner`),
 * порядок тот же — каждое следующее условие перекрывает предыдущее:
 *
 *  1. B — базовый, всё остальное надстраивается;
 *  2. T — есть `signatureTimeStampToken` в неподписанных атрибутах;
 *  3. LT — в `SignedData.crls` есть данные для проверки отзыва;
 *  4. LTA — есть архивная метка времени.
 */
object CadesInspector {

    /** Факты об одном подписанте. */
    data class SignerFacts(
        /** Уровень, который подпись заявляет. */
        val level: AdesLevel,
        /**
         * Сошлась ли привязка `signingCertificateV2` с сертификатом подписанта.
         * `true`, если атрибута нет вовсе: не-AdES подписи проверять не на что.
         */
        val signingCertificateMatches: Boolean,
    )

    /**
     * OID'ы архивных меток. НУЦ выпускает и проверяет только v3 из
     * EN 319 122-1; старые из TS 101 733 распознаём, чтобы честно показать
     * уровень чужой подписи, даже если сами такие не выпускаем.
     */
    private val ARCHIVE_TIMESTAMP_OIDS = listOf(
        DERObjectIdentifier("0.4.0.1733.2.4"), // id-aa-ets-archiveTimestampV3
        DERObjectIdentifier("1.2.840.113549.1.9.16.2.48"), // archive-timestamp-v2
        DERObjectIdentifier("1.2.840.113549.1.9.16.2.27"), // archive-timestamp (v1)
    )

    /** SHA-256: подразумевается, когда `hashAlgorithm` в ESSCertIDv2 опущен (RFC 5035 §4). */
    private const val DEFAULT_ESS_DIGEST_OID = "2.16.840.1.101.3.4.2.1"

    /**
     * Разбирает подпись за один проход. Порядок подписантов совпадает с
     * [kz.ncanode.service.CmsService.verify] — оба идут по `signerInfos`.
     *
     * @param cmsBytes сырой DER подписи: `CMSSignedData` не отдаёт свой
     *   `ContentInfo` наружу, а перекодировать через `getEncoded()` ради
     *   разбора `crls` на крупных CMS незачем
     */
    fun inspect(cmsBytes: ByteArray, provider: Provider): List<SignerFacts> {
        val cms = CMSSignedData(cmsBytes)
        val certificates = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
        val embeddedRevocation = hasEmbeddedRevocation(cmsBytes)

        return cms.signerInfos.signers.map { signerObject ->
            val signer = signerObject as SignerInformation
            val certificate = certificates.getCertificates(signer.sid).firstOrNull() as X509Certificate?
            SignerFacts(
                level = detectLevel(signer, embeddedRevocation),
                signingCertificateMatches = signingCertificateMatches(signer, certificate, provider),
            )
        }
    }

    private fun detectLevel(signer: SignerInformation, embeddedRevocation: Boolean): AdesLevel {
        var level = AdesLevel.B
        val unsigned = signer.unsignedAttributes

        if (unsigned?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
            level = AdesLevel.T
        }
        if (embeddedRevocation) {
            level = AdesLevel.LT
        }
        if (unsigned != null && ARCHIVE_TIMESTAMP_OIDS.any { unsigned.get(it) != null }) {
            level = AdesLevel.LTA
        }
        return level
    }

    /**
     * Сверяет `signingCertificateV2` (RFC 5035) с сертификатом подписанта.
     *
     * Смысл атрибута в том, что он лежит под подписью и намертво привязывает
     * её к конкретному сертификату. Не проверять его — значит принимать
     * заявленный уровень B, не подтверждая единственное, что этот уровень
     * добавляет.
     */
    private fun signingCertificateMatches(
        signer: SignerInformation,
        certificate: X509Certificate?,
        provider: Provider,
    ): Boolean {
        val attribute = signer.signedAttributes?.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
            ?: return true
        if (certificate == null) {
            log.warn("signingCertificateV2 present but signer certificate is not embedded in CMS")
            return false
        }
        return try {
            val signingCertificate = SigningCertificateV2.getInstance(attribute.attrValues.getObjectAt(0))
            val certificateId = signingCertificate.certs.firstOrNull() ?: return false
            val digestOid = certificateId.hashAlgorithm?.objectId?.id ?: DEFAULT_ESS_DIGEST_OID
            val digest = MessageDigest.getInstance(digestOid, provider).digest(certificate.encoded)
            val matches = digest.contentEquals(certificateId.certHash)
            if (!matches) {
                log.warn("signingCertificateV2 hash does not match the signer certificate")
            }
            matches
        } catch (e: Exception) {
            log.warn("Cannot read signingCertificateV2: {}", e.message)
            false
        }
    }

    private fun hasEmbeddedRevocation(cmsBytes: ByteArray): Boolean {
        val contentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(cmsBytes))
        val signedData = SignedData.getInstance(contentInfo.content)
        // В этом же множестве лежат и OCSP-ответы — они заворачиваются в
        // [1] OtherRevocationInfoFormat (RFC 5652 §10.2.1), поэтому для
        // определения уровня достаточно непустоты, разбирать типы не нужно.
        val revocationInfo = signedData.getCRLs()
        return revocationInfo != null && revocationInfo.size() > 0
    }

    private val log = LoggerFactory.getLogger(CadesInspector::class.java)
}
