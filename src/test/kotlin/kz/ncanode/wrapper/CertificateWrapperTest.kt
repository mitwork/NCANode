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
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
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

    // ---- шаблоны и расширения приказа МИИ РК №522/НҚ ----

    test("keyUser EKU includes ORGANIZATION_DIGITAL_SYSTEM for цифровая-система cert") {
        // Шаблон «цифровая система юридического лица» (1.2.398.3.3.4.1.2.6).
        // OID появился в приказе №522/НҚ, но НУЦ выдаёт такие сертификаты уже
        // сейчас — он есть на нашем же тестовом ключе. Нераспознанный OID
        // молча выпадал из keyUser (mapNotNull), и /x509/info занижал шаблон.
        val cert = certFromP12("legal_infosystem_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.keyUser.shouldNotBeNull() shouldContain CertificateKeyUser.ORGANIZATION_DIGITAL_SYSTEM
    }

    test("keyUser EKU includes TREASURY_CLIENT for Казначейство-Клиент cert") {
        val cert = certFromP12("legal_treasury_valid.p12")
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.keyUser.shouldNotBeNull() shouldContain CertificateKeyUser.TREASURY_CLIENT
    }

    test("crlDistributionPoints groups mirrors of one distribution point together") {
        // Внутри одной точки распространения адреса — зеркала одного списка
        // (RFC 5280 §4.2.1.13). Профили НУЦ объявляют пару crl + crl1, и
        // группировка — то, что удерживает нас от загрузки двух копий.
        val cert = certFromP12("individual_valid.p12")
        cert.crlDistributionPoints shouldHaveAtLeastSize 1
        cert.crlDistributionPoints.flatten() shouldBe cert.crlList
    }

    test("freshestCrlDistributionPoints extracts the delta CRL address") {
        // Адрес разностного СОС лежит в freshestCRL (2.5.29.46), а не в
        // cRLDistributionPoints — так и на боевых, и на тестовых сертификатах НУЦ.
        val cert = certFromP12("individual_valid.p12")
        val delta = cert.freshestCrlDistributionPoints.flatten()
        delta shouldHaveAtLeastSize 1
        delta.none { it in cert.crlList } shouldBe true
    }

    test("Subject UID is parsed (digital system OID)") {
        // В шаблоне «цифровая система юридического лица» UID
        // (0.9.2342.19200300.100.1.1) несёт OID самой цифровой системы, в
        // которую по п. 17 Правил разрешено ставить закрытый ключ. Тестового
        // ключа с этим полем в паке НУЦ нет, поэтому сертификат собираем сами
        // — проверяется разбор DN, а не криптография.
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val subject = X500Name("CN=ЦИФРОВАЯ СИСТЕМА,UID=1.2.398.100.500,OU=BIN123456789021,C=KZ")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(
            subject, BigInteger.ONE, Date(now - 86_400_000L), Date(now + 86_400_000L), subject, keyPair.public,
        ).build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        val cert = CertificateWrapper(JcaX509CertificateConverter().getCertificate(holder))

        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.subject.shouldNotBeNull().uid shouldBe "1.2.398.100.500"
        info.subject.shouldNotBeNull().bin shouldBe "123456789021"
    }

    // ---- Правила формирования и проверки подлинности ЭЦП (приказ №500/НҚ) ----

    /**
     * Самоподписанный RSA-сертификат с заданным периодом и расширениями.
     * Криптография здесь не проверяется — `isValid` работает с уже
     * построенными связями `issuerCertificate`, — поэтому важен только состав
     * полей.
     */
    fun syntheticCert(
        cn: String,
        notBefore: Date,
        notAfter: Date,
        keyUsage: KeyUsage? = null,
        issuerCn: String = cn,
    ): CertificateWrapper {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val name = X500Name("CN=$cn")
        val issuerName = X500Name("CN=$issuerCn")
        val builder =
            JcaX509v3CertificateBuilder(issuerName, BigInteger.ONE, notBefore, notAfter, name, keyPair.public)
        if (keyUsage != null) builder.addExtension(Extension.keyUsage, true, keyUsage)
        val holder = builder.build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        return CertificateWrapper(JcaX509CertificateConverter().getCertificate(holder))
    }

    val hourAgo = Date(System.currentTimeMillis() - 3_600_000L)
    val yearAhead = Date(System.currentTimeMillis() + 365L * 86_400_000L)
    val yearAgo = Date(System.currentTimeMillis() - 365L * 86_400_000L)

    test("isValid rejects the leaf when a certificate higher up the chain has expired") {
        // п. 16 Правил: срок действия проверяется у всей цепочки до доверенного
        // корня, и истечение любого звена — отрицательный результат. Раньше
        // смотрели только на непосредственного издателя, так что протухший
        // корень оставался незамеченным.
        val root = syntheticCert("expired root", yearAgo, hourAgo)
        val intermediate = syntheticCert("intermediate", hourAgo, yearAhead, issuerCn = "expired root")
        val leaf = syntheticCert("leaf", hourAgo, yearAhead, issuerCn = "intermediate")
        intermediate.issuerCertificate = root
        leaf.issuerCertificate = intermediate

        leaf.isValid(Date(), checkOcsp = false, checkCrl = false) shouldBe false
    }

    test("isValid accepts the leaf when the whole chain is within its validity period") {
        val root = syntheticCert("root", hourAgo, yearAhead)
        val intermediate = syntheticCert("intermediate", hourAgo, yearAhead, issuerCn = "root")
        val leaf = syntheticCert("leaf", hourAgo, yearAhead, issuerCn = "intermediate")
        // Самоподписанный корень CaService ссылает сам на себя — обход обязан
        // на этом остановиться, а не зациклиться.
        root.issuerCertificate = root
        intermediate.issuerCertificate = root
        leaf.issuerCertificate = intermediate

        leaf.isValid(Date(), checkOcsp = false, checkCrl = false) shouldBe true
    }

    test("isValid rejects a certificate whose keyUsage forbids signing") {
        // п. 16 Правил: назначение ключа должно допускать подпись. Ключ только
        // для шифрования подписывать не может, каким бы валидным ни был сам
        // сертификат.
        val cipherOnly = syntheticCert("cipher only", hourAgo, yearAhead, KeyUsage(KeyUsage.keyEncipherment))
        cipherOnly.issuerCertificate = cipherOnly
        cipherOnly.permitsSignature() shouldBe false
        cipherOnly.isValid(Date(), checkOcsp = false, checkCrl = false) shouldBe false
    }

    test("isValid allows a certificate without the keyUsage extension") {
        // RFC 5280 §4.2.1.3: расширение опционально, его отсутствие не
        // ограничивает назначение ключа.
        val noKeyUsage = syntheticCert("no key usage", hourAgo, yearAhead)
        noKeyUsage.issuerCertificate = noKeyUsage
        noKeyUsage.permitsSignature() shouldBe true
        noKeyUsage.isValid(Date(), checkOcsp = false, checkCrl = false) shouldBe true
    }

    test("NCA certificate publishes its policy OID") {
        // п. 16 Правил требует сверять номер политики сертификата с условиями
        // её применения. Сами условия задаёт УЦ, поэтому мы публикуем номер —
        // у сертификатов НУЦ это 1.2.398.3.3.2.
        val cert = certFromP12("legal_ceo_valid.p12")
        cert.certificatePolicies shouldContain "1.2.398.3.3.2"
        val info = cert.toCertificateInfo(Date(), checkOcsp = false, checkCrl = false)
        info.policies.shouldNotBeNull() shouldContain "1.2.398.3.3.2"
    }

    test("isValid rejects the certificate when the only CRL is past its validity period") {
        // п. 18 Правил: истёкший CRL — отрицательный результат проверки отзыва.
        // Опереться больше не на что: OCSP не запрашивали.
        val cert = syntheticCert("leaf", hourAgo, yearAhead)
        cert.issuerCertificate = cert
        cert.crlStatus = CrlStatus(result = CrlResult.EXPIRED)

        cert.isValid(Date(), checkOcsp = false, checkCrl = true) shouldBe false
    }

    test("isValid tolerates an expired CRL when OCSP answered positively") {
        // п. 16 Правил допускает проверку отзыва «посредством сервиса OCSP либо
        // CRL»: авторитетный ACTIVE от респондера — самостоятельный
        // положительный результат, и протухший список его не отменяет.
        val cert = syntheticCert("leaf", hourAgo, yearAhead)
        cert.issuerCertificate = cert
        cert.crlStatus = CrlStatus(result = CrlResult.EXPIRED)
        cert.ocspStatus = listOf(OcspStatus(result = OcspResult.ACTIVE))

        cert.isValid(Date(), checkOcsp = true, checkCrl = true) shouldBe true
    }
})
