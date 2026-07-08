package kz.ncanode.wrapper

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveAtLeastSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.dto.certificate.CertificateKeyUsage
import kz.ncanode.dto.certificate.CertificateKeyUser
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import java.io.File
import java.util.Date

class CertificateWrapperTest : FunSpec({

    val kalkan = KalkanWrapper(KalkanProvider())

    fun certFromP12(name: String): CertificateWrapper =
        kalkan.read(
            TestResources.loadAsBase64("p12/$name"),
            null,
            TestResources.P12_PASSWORD,
        ).certificate

    test("fromBytes parses a root CA cert (NCA test root)") {
        val bytes = TestResources.loadBytes("ca/root_test_gost_2022.cer")
        val cert = CertificateWrapper.fromBytes(bytes)
        cert.shouldNotBeNull()
        // Root CA: subject == issuer.
        cert.subjectX500Principal shouldBe cert.issuerX500Principal
    }

    test("fromBytes returns null for non-cert bytes") {
        CertificateWrapper.fromBytes(byteArrayOf(0x01, 0x02, 0x03)) shouldBe null
    }

    test("fromFile reads cert from disk") {
        val tmp = File.createTempFile("ncanode-test-", ".cer")
        try {
            tmp.writeBytes(TestResources.loadBytes("ca/nca_gost2022_test.cer"))
            val cert = CertificateWrapper.fromFile(tmp)
            cert.shouldNotBeNull()
        } finally {
            tmp.delete()
        }
    }

    test("fromFile returns null for nonexistent file") {
        CertificateWrapper.fromFile(File("/nonexistent/path/garbage.cer")) shouldBe null
    }

    test("Individual cert Subject DN parsed correctly") {
        val cert = certFromP12("individual_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)

        val subject = info.subject
        subject.shouldNotBeNull()
        // Физлицо: IIN, CN, SURNAME, G(givenName).
        subject.iin.shouldNotBeNull()
        subject.commonName.shouldNotBeNull()
        // Юр.лицо-специфичные поля у физлица должны быть null.
        subject.bin shouldBe null
    }

    test("Legal CEO cert carries BIN (not IIN) in Subject DN") {
        val cert = certFromP12("legal_ceo_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)

        val subject = info.subject
        subject.shouldNotBeNull()
        // Юр.лицо CEO: BIN присутствует. У некоторых cert'ов также есть IIN
        // CEO (физлица как руководителя), но BIN — обязателен.
        subject.bin.shouldNotBeNull()
        subject.organization.shouldNotBeNull()
    }

    test("CertificateInfo for valid (online-status-ignored) cert has notBefore/notAfter") {
        val cert = certFromP12("individual_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)

        info.notBefore.shouldNotBeNull()
        info.notAfter.shouldNotBeNull()
        info.serialNumber.shouldNotBeNull()
        info.signAlg.shouldNotBeNull()
        info.publicKey.shouldNotBeNull()
    }

    test("keyUsage extracted from cert (Individual -> SIGN)") {
        val cert = certFromP12("individual_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.keyUsage shouldNotBe null
        info.keyUsage shouldNotBe CertificateKeyUsage.UNKNOWN
    }

    test("keyUser EKU includes INDIVIDUAL for физлицо cert") {
        val cert = certFromP12("individual_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.keyUser.shouldNotBeNull() shouldContain CertificateKeyUser.INDIVIDUAL
    }

    test("keyUser EKU includes CEO for первый-руководитель cert") {
        val cert = certFromP12("legal_ceo_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.keyUser.shouldNotBeNull() shouldContain CertificateKeyUser.CEO
    }

    test("keyUser EKU includes EMPLOYEE for сотрудник-организации cert") {
        val cert = certFromP12("legal_employee_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.keyUser.shouldNotBeNull() shouldContain CertificateKeyUser.EMPLOYEE
    }

    test("crlList extracts CRL DistributionPoints URLs from cert extension") {
        val cert = certFromP12("individual_valid.p12")
        // Real NCA cert'ы кладут CRL DP в extension; должен прийти хотя бы один.
        cert.crlList shouldHaveAtLeastSize 1
        cert.crlList.first().protocol shouldBe "http"
    }

    test("ocspUrls extracts AIA id-ad-ocsp URLs from cert extension") {
        val cert = certFromP12("individual_valid.p12")
        // Real NCA cert'ы кладут AIA OCSP URL — primary источник по RFC 5280 §4.2.2.1.
        cert.ocspUrls shouldHaveAtLeastSize 1
    }

    test("isDateValid true for cert at current moment (valid period in 2026)") {
        val cert = certFromP12("individual_valid.p12")
        cert.isDateValid() shouldBe true
    }

    test("isDateValid false for cert outside its notBefore/notAfter window") {
        val cert = certFromP12("individual_valid.p12")
        // Дата задолго до notBefore — должна провалиться.
        cert.isDateValid(Date(0)) shouldBe false
    }

    test("expired cert returns isDateValid=false for current date") {
        // expired_*.p12 — старого периода 2024-2025, текущая дата 2026+.
        val cert = certFromP12("expired_individual.p12")
        cert.isDateValid() shouldBe false
    }

    test("verify() returns true against issuing CA public key, false against unrelated CA") {
        val cert = certFromP12("individual_valid.p12")
        val nca = CertificateWrapper.fromBytes(
            TestResources.loadBytes("ca/nca_gost2022_test.cer")
        )
        nca.shouldNotBeNull()
        cert.verify(nca.publicKey) shouldBe true

        // Корневой не подписывал end-entity напрямую.
        val root = CertificateWrapper.fromBytes(
            TestResources.loadBytes("ca/root_test_gost_2022.cer")
        )
        root.shouldNotBeNull()
        cert.verify(root.publicKey) shouldBe false
    }

    // --- isValid: темпоральный отзов относительно времени подписи (CAdES-T) ---
    //
    // Воспроизводит прод-кейс: подпись поставлена валидным ключом, позже ключ
    // перевыпущен (старый отозван reason=SUPERSEDED). Проверка с TSP-меткой
    // ведётся на genTime (момент подписи), а не на "сейчас".

    // Берём реальный cert (валиден в 2026) + реальный CA как issuer; точку
    // проверки кладём в середину окна валидности, отзыв — на час позже.
    fun signedCertWithIssuer(): Pair<CertificateWrapper, Date> {
        val cert = certFromP12("individual_valid.p12")
        cert.issuerCertificate = CertificateWrapper.fromBytes(
            TestResources.loadBytes("ca/nca_gost2022_test.cer")
        )
        val nb = cert.x509Certificate.notBefore.time
        val na = cert.x509Certificate.notAfter.time
        return cert to Date((nb + na) / 2)
    }

    test("isValid: OCSP revoked SUPERSEDED AFTER signing time stays valid") {
        val (cert, signingTime) = signedCertWithIssuer()
        val revokedAfter = Date(signingTime.time + 3_600_000L)
        cert.ocspStatus = listOf(
            OcspStatus(result = OcspResult.REVOKED, revocationTime = revokedAfter, revocationReason = 4)
        )
        cert.isValid(signingTime, checkOcsp = true, checkCrl = false) shouldBe true
    }

    test("isValid: OCSP revoked SUPERSEDED BEFORE signing time is invalid") {
        val (cert, signingTime) = signedCertWithIssuer()
        val revokedBefore = Date(signingTime.time - 3_600_000L)
        cert.ocspStatus = listOf(
            OcspStatus(result = OcspResult.REVOKED, revocationTime = revokedBefore, revocationReason = 4)
        )
        cert.isValid(signingTime, checkOcsp = true, checkCrl = false) shouldBe false
    }

    test("isValid: OCSP revoked keyCompromise after signing is invalid (retroactive)") {
        val (cert, signingTime) = signedCertWithIssuer()
        val revokedAfter = Date(signingTime.time + 3_600_000L)
        cert.ocspStatus = listOf(
            OcspStatus(result = OcspResult.REVOKED, revocationTime = revokedAfter, revocationReason = 1)
        )
        cert.isValid(signingTime, checkOcsp = true, checkCrl = false) shouldBe false
    }

    test("isValid: CRL revoked SUPERSEDED after signing stays valid") {
        val (cert, signingTime) = signedCertWithIssuer()
        val revokedAfter = Date(signingTime.time + 3_600_000L)
        cert.crlStatus = CrlStatus(
            result = CrlResult.REVOKED, revocationDate = revokedAfter, reason = "SUPERSEDED"
        )
        cert.isValid(signingTime, checkOcsp = false, checkCrl = true) shouldBe true
    }

    test("isValid: CRL revoked SUPERSEDED before signing is invalid") {
        val (cert, signingTime) = signedCertWithIssuer()
        val revokedBefore = Date(signingTime.time - 3_600_000L)
        cert.crlStatus = CrlStatus(
            result = CrlResult.REVOKED, revocationDate = revokedBefore, reason = "SUPERSEDED"
        )
        cert.isValid(signingTime, checkOcsp = false, checkCrl = true) shouldBe false
    }

    // --- isValid: OCSP UNAVAILABLE → CRL fallback (availability-деградация) ---
    //
    // Сетевая недоступность OCSP-responder'а (UNAVAILABLE) не роняет верификацию,
    // если запрошены обе проверки и есть СВЕЖИЙ CRL-вердикт ACTIVE. Любой
    // авторитетный плохой ответ (UNKNOWN, непрощённый REVOKED) остаётся фатальным.

    test("isValid: OCSP unavailable + fresh CRL ACTIVE falls back to valid") {
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = listOf(OcspStatus(result = OcspResult.UNAVAILABLE, message = "network down"))
        cert.crlStatus = CrlStatus(result = CrlResult.ACTIVE, fresh = true)
        cert.isValid(date, checkOcsp = true, checkCrl = true) shouldBe true
    }

    test("isValid: OCSP unavailable + stale CRL ACTIVE is invalid") {
        // Протухший по nextUpdate CRL не может единолично реабилитировать cert:
        // окно false-valid при долгом падении OCSP должно быть ограничено.
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = listOf(OcspStatus(result = OcspResult.UNAVAILABLE))
        cert.crlStatus = CrlStatus(result = CrlResult.ACTIVE, fresh = false)
        cert.isValid(date, checkOcsp = true, checkCrl = true) shouldBe false
    }

    test("isValid: OCSP unavailable + CRL UNAVAILABLE is invalid") {
        // Оба канала недоступны — реабилитировать нечем, fail-closed.
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = listOf(OcspStatus(result = OcspResult.UNAVAILABLE))
        cert.crlStatus = CrlStatus(result = CrlResult.UNAVAILABLE)
        cert.isValid(date, checkOcsp = true, checkCrl = true) shouldBe false
    }

    test("isValid: OCSP unavailable without CRL check requested is invalid") {
        // Строгий OCSP-only режим (revocationCheck=[OCSP]): fallback'а некуда,
        // недоступность фатальна — прежнее поведение.
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = listOf(OcspStatus(result = OcspResult.UNAVAILABLE))
        cert.isValid(date, checkOcsp = true, checkCrl = false) shouldBe false
    }

    test("isValid: OCSP UNKNOWN is fatal even with fresh CRL ACTIVE") {
        // UNKNOWN = ответ получен, но доверия нет (nonce/подпись/статус) —
        // security fail-closed, деградация на CRL запрещена.
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = listOf(OcspStatus(result = OcspResult.UNKNOWN))
        cert.crlStatus = CrlStatus(result = CrlResult.ACTIVE, fresh = true)
        cert.isValid(date, checkOcsp = true, checkCrl = true) shouldBe false
    }

    test("isValid: mixed OCSP [ACTIVE, UNAVAILABLE] is valid — one answer suffices") {
        // Один responder ответил положительно, второй недоступен: OCSP-вердикт
        // есть, недоступность остальных URL нефатальна.
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = listOf(
            OcspStatus(result = OcspResult.ACTIVE),
            OcspStatus(result = OcspResult.UNAVAILABLE),
        )
        cert.isValid(date, checkOcsp = true, checkCrl = false) shouldBe true
    }

    test("isValid: CRL UNAVAILABLE alone is non-fatal (legacy CA without published CRL)") {
        // Историческое поведение: cert от CA без опубликованного CRL молча
        // проходил CRL-проверку. UNAVAILABLE сохраняет это, честно отражаясь
        // в revocations[] вместо фиктивного ACTIVE.
        val (cert, date) = signedCertWithIssuer()
        cert.crlStatus = CrlStatus(result = CrlResult.UNAVAILABLE)
        cert.isValid(date, checkOcsp = false, checkCrl = true) shouldBe true
    }

    test("isValid: empty OCSP status list needs CRL fallback (no responder URLs at all)") {
        // Пустой список = ни одного URL (нет AIA и конфиг пуст) — ответа нет,
        // как и при недоступности. Раньше пустой список проходил вакуумно
        // (all{} == true); теперь требуется fallback-основание.
        val (cert, date) = signedCertWithIssuer()
        cert.ocspStatus = emptyList()
        cert.crlStatus = CrlStatus(result = CrlResult.ACTIVE, fresh = true)
        cert.isValid(date, checkOcsp = true, checkCrl = true) shouldBe true
        cert.crlStatus = CrlStatus(result = CrlResult.UNAVAILABLE)
        cert.isValid(date, checkOcsp = true, checkCrl = true) shouldBe false
    }
})
