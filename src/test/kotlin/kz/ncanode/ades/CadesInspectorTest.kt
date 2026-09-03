package kz.ncanode.ades

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.DERSet
import kz.gov.pki.kalkan.asn1.DERUTF8String
import kz.gov.pki.kalkan.asn1.cms.Attribute
import kz.gov.pki.kalkan.asn1.cms.AttributeTable
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.ncanode.TestResources
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.wrapper.KalkanWrapper
import java.security.cert.CertStore
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509CRL

/**
 * Определение заявленного уровня CAdES и сверка привязки к сертификату.
 *
 * Уровни LT и LTA мы пока не выпускаем, но обязаны их **распознавать** —
 * подписи такого уровня приходят от NCALayer уже сейчас. Поэтому здесь они
 * собираются вручную: LT — реальным CRL в `SignedData.crls`, LTA — архивным
 * атрибутом. Это ровно то, на что смотрит детектор: уровень определяется
 * наличием элементов, а не их валидностью.
 */
class CadesInspectorTest : FunSpec({

    val provider = KalkanProvider()
    val kalkanWrapper = KalkanWrapper(provider)

    fun keyStore(name: String) = kalkanWrapper.read(
        TestResources.loadAsBase64("p12/$name"), null, TestResources.P12_PASSWORD,
    )

    val signerKeyStore = keyStore("individual_valid.p12")
    val signerCertificate = signerKeyStore.certificate.x509Certificate

    val testCrl = CertificateFactory.getInstance("X.509")
        .generateCRL(TestResources.loadBytes("crl/nca_gost2022_test.crl").inputStream()) as X509CRL

    /** Подписывает данные атрибутами уровня B; [extra] попадает в SignedData.crls. */
    fun sign(extra: List<Any> = emptyList()): CMSSignedData {
        val generator = CMSSignedDataGenerator()
        val digestOid = getDigestAlgorithmOidBYSignAlgorithmOid(signerCertificate.sigAlgOID)
        generator.addSigner(
            signerKeyStore.privateKey,
            signerCertificate,
            digestOid,
            CadesAttributes.signedAttributes(signerCertificate, digestOid, provider),
            null as AttributeTable?,
        )
        generator.addCertificatesAndCRLs(
            CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(listOf<Any>(signerCertificate) + extra),
                KalkanProvider.PROVIDER_NAME,
            ),
        )
        return generator.generate(
            CMSProcessableByteArray("payload".toByteArray()),
            true,
            KalkanProvider.PROVIDER_NAME,
        )
    }

    fun withUnsignedAttribute(cms: CMSSignedData, oid: String): CMSSignedData {
        val signer = cms.signerInfos.signers.first() as SignerInformation
        val vector = signer.unsignedAttributes?.toASN1EncodableVector() ?: ASN1EncodableVector()
        vector.add(Attribute(DERObjectIdentifier(oid), DERSet(DERUTF8String("stub"))))
        val updated = SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(vector))
        return CMSSignedData.replaceSigners(cms, SignerInformationStore(listOf(updated)))
    }

    test("plain signed attributes are level B") {
        val facts = CadesInspector.inspect(sign().encoded, provider)
        facts.size shouldBe 1
        facts[0].level shouldBe AdesLevel.B
        facts[0].signingCertificateMatches shouldBe true
    }

    test("signature timestamp raises the detected level to T") {
        val cms = withUnsignedAttribute(sign(), "1.2.840.113549.1.9.16.2.14") // id-aa-signatureTimeStampToken
        CadesInspector.inspect(cms.encoded, provider)[0].level shouldBe AdesLevel.T
    }

    test("revocation material embedded in SignedData.crls raises the level to LT") {
        // Так строит LT реализация НУЦ: материал для проверки кладётся не в
        // атрибуты certValues/revocationValues, а в сам SignedData.
        CadesInspector.inspect(sign(extra = listOf(testCrl)).encoded, provider)[0].level shouldBe AdesLevel.LT
    }

    test("archive timestamp raises the level to LTA") {
        val cms = withUnsignedAttribute(sign(extra = listOf(testCrl)), "0.4.0.1733.2.4")
        CadesInspector.inspect(cms.encoded, provider)[0].level shouldBe AdesLevel.LTA
    }

    test("legacy archive timestamp OIDs are recognised as LTA too") {
        // Сами такие не выпускаем, но чужую подпись обязаны назвать честно.
        for (oid in listOf("1.2.840.113549.1.9.16.2.48", "1.2.840.113549.1.9.16.2.27")) {
            CadesInspector.inspect(withUnsignedAttribute(sign(), oid).encoded, provider)[0].level shouldBe
                AdesLevel.LTA
        }
    }

    test("level detection ignores whether the elements are valid") {
        // Атрибут метки времени с мусором вместо токена — уровень всё равно T.
        // Валидность проверяется отдельно и отдельно же сообщается.
        val cms = withUnsignedAttribute(sign(), "1.2.840.113549.1.9.16.2.14")
        CadesInspector.inspect(cms.encoded, provider)[0].level shouldBe AdesLevel.T
    }

    test("signingCertificateV2 pointing at another certificate is rejected") {
        // Подпись настоящая, ключ настоящий — подменён только хэш в привязке.
        // Без проверки ESS такая подпись прошла бы как валидная.
        val foreignCertificate = keyStore("legal_ceo_valid.p12").certificate.x509Certificate
        val digestOid = getDigestAlgorithmOidBYSignAlgorithmOid(signerCertificate.sigAlgOID)

        val generator = CMSSignedDataGenerator()
        generator.addSigner(
            signerKeyStore.privateKey,
            signerCertificate,
            digestOid,
            // Атрибуты собраны для ЧУЖОГО сертификата.
            CadesAttributes.signedAttributes(foreignCertificate, digestOid, provider),
            null as AttributeTable?,
        )
        generator.addCertificatesAndCRLs(
            CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(listOf(signerCertificate)),
                KalkanProvider.PROVIDER_NAME,
            ),
        )
        val cms = generator.generate(
            CMSProcessableByteArray("payload".toByteArray()),
            true,
            KalkanProvider.PROVIDER_NAME,
        )

        // Криптографически подпись сходится — расходится только привязка.
        val signer = cms.signerInfos.signers.first() as SignerInformation
        signer.verify(signerCertificate, KalkanProvider.PROVIDER_NAME) shouldBe true

        CadesInspector.inspect(cms.encoded, provider)[0].signingCertificateMatches shouldBe false
    }
})
