package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.shouldBe
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.ncanode.TestResources
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.util.getTspHashAlgorithmByOid
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.security.cert.X509Certificate

/**
 * Гард-тест: реальный TSA-сертификат НУЦ (test.pki.gov.kz) должен
 * соответствовать RFC 3161 §2.3 — id-kp-timeStamping единственный EKU и
 * помечен critical. На эту конформность опирается строгая проверка в
 * [TspService.verify] (audit fix 3.1): если НУЦ когда-нибудь сменит профиль
 * TSA, этот тест упадёт первым и подскажет ослабить проверку. Печатает
 * фактические значения (маркер `TSA-CONFORMANCE-PROBE`).
 */
@SpringBootTest
@ActiveProfiles("test")
class TsaCertDiagnosticTest(
    @param:Autowired private val tspService: TspService,
    @param:Autowired private val kalkanWrapper: KalkanWrapper,
) : FunSpec({

    extension(SpringExtension)

    test("TSA certificate EKU/criticality conformance to RFC 3161 §2.3") {
        val cert = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null,
            TestResources.P12_PASSWORD,
        ).certificate.x509Certificate

        val token = tspService.create(
            "probe".toByteArray(),
            getTspHashAlgorithmByOid(cert.sigAlgOID),
            TsaPolicy.TSA_GOST2015_POLICY.policyId,
        )

        val cms = CMSSignedData(token.encoded)
        val signer = cms.signerInfos.signers.iterator().next() as SignerInformation
        val tsaCert = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            .getCertificates(signer.sid).iterator().next() as X509Certificate

        val eku = tsaCert.extendedKeyUsage
        val critical = tsaCert.criticalExtensionOIDs
        println("TSA-CONFORMANCE-PROBE EKU=$eku")
        println("TSA-CONFORMANCE-PROBE EKU.size=${eku?.size} soleEku=${eku?.size == 1}")
        println("TSA-CONFORMANCE-PROBE criticalExtOIDs=$critical")
        println("TSA-CONFORMANCE-PROBE ekuMarkedCritical=${critical?.contains("2.5.29.37")}")

        // На эти инварианты опирается строгая проверка TspService.verify (3.1).
        eku shouldBe listOf("1.3.6.1.5.5.7.3.8")           // sole id-kp-timeStamping
        (critical?.contains("2.5.29.37") ?: false) shouldBe true  // EKU critical
    }
})
