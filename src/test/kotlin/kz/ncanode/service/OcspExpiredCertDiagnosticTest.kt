package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldNotBeEmpty
import kz.ncanode.TestResources
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

/**
 * Диагностический пробник: отвечает ли OCSP НУЦ (test.pki.gov.kz) по
 * сертификату, который УЖЕ ИСТЁК (`expired_individual.p12`, период
 * 2024-10 .. 2025-10), или возвращает UNKNOWN.
 *
 * Это эмпирически решает, нужен ли CAdES-X-Long (вшитые revocation-values):
 *  - OCSP отдаёт ACTIVE/REVOKED по истёкшему cert'у → live-проверки на verify
 *    достаточно навсегда, темпорального фикса (#26) хватает;
 *  - OCSP отдаёт UNKNOWN → долгосрочная проверка требует вшивать
 *    revocation-данные в момент приёма подписи (augmentation до X-Long).
 *
 * Намеренно НЕ ассертит конкретный исход — он и есть предмет наблюдения;
 * проверяет только что responder доступен. Вердикт печатается с маркером
 * `OCSP-EXPIRED-PROBE`. Требует сети к test.pki.gov.kz.
 */
@SpringBootTest
@ActiveProfiles("test")
class OcspExpiredCertDiagnosticTest(
    @param:Autowired private val ocspService: OcspService,
    @param:Autowired private val kalkanWrapper: KalkanWrapper,
) : FunSpec({

    extension(SpringExtension)

    test("OCSP responder behaviour for an already-expired NCA certificate") {
        val cert = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/expired_individual.p12"),
            null,
            TestResources.P12_PASSWORD,
        ).certificate

        val issuer = CertificateWrapper.fromBytes(
            TestResources.loadBytes("ca/nca_gost2022_test.cer"),
        )
        requireNotNull(issuer) { "Issuer CA cert must load" }
        cert.issuerCertificate = issuer

        val statuses = ocspService.verify(cert, issuer)
        statuses.shouldNotBeEmpty()

        statuses.forEachIndexed { i, s ->
            println(
                "OCSP-EXPIRED-PROBE [$i] url=${s.url} result=${s.result} " +
                    "revocationReason=${s.revocationReason} revocationTime=${s.revocationTime} message=${s.message}",
            )
        }

        val verdict = when {
            statuses.any { it.result == OcspResult.REVOKED } ->
                "REVOKED — OCSP знает истёкший cert → live-проверки достаточно, X-Long не обязателен"
            statuses.any { it.result == OcspResult.ACTIVE } ->
                "ACTIVE — OCSP знает истёкший cert → live-проверки достаточно, X-Long не обязателен"
            else ->
                "UNKNOWN — OCSP не знает истёкший cert → для долгосрочной проверки нужен CAdES-X-Long"
        }
        println("OCSP-EXPIRED-PROBE VERDICT: $verdict")
    }
})
