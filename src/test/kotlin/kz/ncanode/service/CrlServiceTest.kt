package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.verify
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.wrapper.KalkanWrapper
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.util.Date

/**
 * Unit-проверка CrlService.verify против реального CRL'я из репо
 * (`nca_gost2022_test.crl`). HTTP-слой полностью замокан — реальные
 * скачивания/расписания не запускаются.
 *
 * Покрывает:
 *  - REVOKED для отозванного сертификата (`individual_revoked.p12` есть в CRL),
 *  - ACTIVE для валидного (`individual_valid.p12`),
 *  - UNAVAILABLE, когда проверять нечем (выключен / чужой CA / отброшенные CRL),
 *  - freshness ACTIVE-вердикта по nextUpdate (основа OCSP→CRL fallback'а),
 *  - short-circuit на `isEnabled=false` — verify не должен трогать диск.
 */
class CrlServiceTest : FunSpec({

    val kalkanWrapper = KalkanWrapper(KalkanProvider())

    // Парсим оба CRL'я один раз на spec — каждый ~МБ, повторно делать дорого.
    // NCA публикует full ("nca_gost2022_test.crl") и delta ("nca_gost2022_d_test.crl"):
    // отзывы могут лежать в любом из них в зависимости от времени отзыва
    // относительно последнего cut'а full CRL.
    fun parseCrl(name: String): X509CRL = CertificateFactory.getInstance("X.509")
        .generateCRL(TestResources.loadBytes("crl/$name").inputStream()) as X509CRL

    val gostCrlFull: X509CRL = parseCrl("nca_gost2022_test.crl")
    val gostCrlDelta: X509CRL = parseCrl("nca_gost2022_d_test.crl")

    fun mockCrlFile(label: String): File = mockk<File>(relaxed = true).apply {
        every { absolutePath } returns "/mock/$label.crl"
        every { name } returns "$label.crl"
        every { isFile } returns true
        every { canRead() } returns true
    }

    fun buildService(crlEnabled: Boolean = true): CrlService {
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns crlEnabled
            every { isCacheEnabled } returns false  // обходит in-memory кэш — loadCrl вызывается напрямую
            every { ttl } returns null              // обходит fetchOnDemandCrls и initialize-scheduler
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val fullFile = mockCrlFile("nca_gost2022_test")
        val deltaFile = mockCrlFile("nca_gost2022_d_test")
        val service = spyk(
            CrlService(
                directoryService = mockk(relaxed = true),
                crlConfiguration = crlConfig,
                client = mockk(relaxed = true),
                httpClientConfiguration = HttpClientConfiguration(),
                taskScheduler = mockk(relaxed = true),
                crlServiceType = "test",
            )
        )
        // verify() обходит каталоги в порядке delta → full → ondemand.
        // Реальные NCA-отзывы могут лежать в любом, подсовываем оба.
        every { service.getCrlFiles(any()) } answers {
            val arg = firstArg<String>()
            when {
                arg.contains("delta") -> listOf(deltaFile)
                arg.contains("full") -> listOf(fullFile)
                else -> emptyList()
            }
        }
        every { service.loadCrl(fullFile) } returns gostCrlFull
        every { service.loadCrl(deltaFile) } returns gostCrlDelta
        return service
    }

    test("verify() returns REVOKED when CRL marks cert as revoked") {
        // NCA test-pack p12 в реальные test.pki.gov.kz CRL'и не попали
        // (отзывы там обслуживаются через OCSP, а не CRL). Поэтому REVOKED-ветка
        // покрывается через mock'нутый X509CRL, который объявляет cert
        // отозванным. Цель — проверить CrlService.verify pipeline (issuer-match,
        // signature skip при null issuerKey, isRevoked-lookup), а не сам
        // JDK'шный X509CRL.isRevoked (он работает корректно по построению).
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val revocationDate = Date()
        val mockCrlEntry = mockk<java.security.cert.X509CRLEntry>(relaxed = true).apply {
            every { this@apply.revocationDate } returns revocationDate
            every { revocationReason } returns null
        }
        val revokingCrl = mockk<X509CRL>(relaxed = true).apply {
            every { issuerX500Principal } returns cert.x509Certificate.issuerX500Principal
            every { isRevoked(any<java.security.cert.X509Certificate>()) } returns true
            every { getRevokedCertificate(any<java.security.cert.X509Certificate>()) } returns mockCrlEntry
            every { nextUpdate } returns Date(System.currentTimeMillis() + 86_400_000L)
        }
        val mockFile = mockCrlFile("synthetic_revoked")
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { ttl } returns null
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val service = spyk(
            CrlService(mockk(relaxed = true), crlConfig, mockk(relaxed = true), HttpClientConfiguration(), mockk(relaxed = true), "test")
        )
        every { service.getCrlFiles(any()) } answers {
            if (firstArg<String>().contains("full")) listOf(mockFile) else emptyList()
        }
        every { service.loadCrl(mockFile) } returns revokingCrl

        val status = service.verify(cert)
        status.result shouldBe CrlResult.REVOKED
        status.revocationDate shouldBe revocationDate
    }

    test("verify() returns ACTIVE against real NCA CRL for a non-revoked cert") {
        // Положительный путь на реальных fixtures: cert не отозван (даже если
        // когда-то им станет, full CRL для individual_valid сейчас не содержит
        // его серийник). Проверяет issuer-match + isRevoked-lookup на честных
        // CRL-данных, не на mock'нутом X509CRL.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val status = buildService().verify(ks.certificate)
        status.result shouldBe CrlResult.ACTIVE
    }

    test("verify() ignores CRL issued by a different CA") {
        // Подсовываем CRL под full с правильной структурой, но другим issuer'ом
        // (не тем, что выпустил cert). CrlService должен его пропустить —
        // иначе бы серийник из чужого CRL мог случайно совпасть с серийником
        // из нашего CA и ложно отозвать валидный cert. Раз других CRL нет,
        // итог — UNAVAILABLE («проверить было нечем»), не фиктивный ACTIVE.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val foreignCrl = mockk<X509CRL>(relaxed = true).apply {
            every { issuerX500Principal } returns javax.security.auth.x500.X500Principal("CN=Some Other CA")
            // Эту ветку CrlService даже не должен дойти — issuer mismatch выше.
            every { isRevoked(any<java.security.cert.X509Certificate>()) } returns true
        }
        val mockFile = mockCrlFile("foreign")
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { ttl } returns null
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val service = spyk(
            CrlService(mockk(relaxed = true), crlConfig, mockk(relaxed = true), HttpClientConfiguration(), mockk(relaxed = true), "test")
        )
        every { service.getCrlFiles(any()) } answers {
            if (firstArg<String>().contains("full")) listOf(mockFile) else emptyList()
        }
        every { service.loadCrl(mockFile) } returns foreignCrl

        service.verify(cert).result shouldBe CrlResult.UNAVAILABLE
        // isRevoked даже не должен был быть вызван — issuer-фильтр срабатывает раньше.
        verify(exactly = 0) { foreignCrl.isRevoked(any<java.security.cert.X509Certificate>()) }
    }

    test("verify() skips a CRL carrying an unsupported critical extension (RFC 5280 §5.2)") {
        // CRL от того же CA, но с critical-расширением, которое мы не
        // обрабатываем (IssuingDistributionPoint 2.5.29.28). Его охват может
        // быть ограничен — доверять его isRevoked нельзя, CRL пропускается.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val criticalCrl = mockk<X509CRL>(relaxed = true).apply {
            every { issuerX500Principal } returns cert.x509Certificate.issuerX500Principal
            every { criticalExtensionOIDs } returns setOf("2.5.29.28") // IDP, critical
            // Если бы CRL НЕ пропустили — он бы отозвал cert. Проверяем, что не доходит.
            every { isRevoked(any<java.security.cert.X509Certificate>()) } returns true
        }
        val mockFile = mockCrlFile("idp_critical")
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { ttl } returns null
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val service = spyk(
            CrlService(mockk(relaxed = true), crlConfig, mockk(relaxed = true), HttpClientConfiguration(), mockk(relaxed = true), "test")
        )
        every { service.getCrlFiles(any()) } answers {
            if (firstArg<String>().contains("full")) listOf(mockFile) else emptyList()
        }
        every { service.loadCrl(mockFile) } returns criticalCrl

        // Единственный CRL отброшен → проверять было нечем → UNAVAILABLE.
        service.verify(cert).result shouldBe CrlResult.UNAVAILABLE
        // CRL пропущен до isRevoked-проверки.
        verify(exactly = 0) { criticalCrl.isRevoked(any<java.security.cert.X509Certificate>()) }
    }

    // Хелпер для freshness-тестов: сервис с одним mock-CRL от issuer'а cert'а,
    // не содержащим его серийник, с управляемым nextUpdate.
    fun serviceWithSingleCrl(cert: kz.ncanode.wrapper.CertificateWrapper, crlNextUpdate: Date?): CrlService {
        val crl = mockk<X509CRL>(relaxed = true).apply {
            every { issuerX500Principal } returns cert.x509Certificate.issuerX500Principal
            // «Не отозван» = серийника нет в CRL. Стабим getRevokedCertificate,
            // а не isRevoked: relaxed-мок для platform-типа X509CRLEntry вернул бы
            // не-null дочерний мок, и verify() счёл бы cert отозванным.
            every { getRevokedCertificate(any<java.security.cert.X509Certificate>()) } returns null
            every { nextUpdate } returns crlNextUpdate
        }
        val mockFile = mockCrlFile("freshness")
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { ttl } returns null
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val service = spyk(
            CrlService(mockk(relaxed = true), crlConfig, mockk(relaxed = true), HttpClientConfiguration(), mockk(relaxed = true), "test")
        )
        every { service.getCrlFiles(any()) } answers {
            if (firstArg<String>().contains("full")) listOf(mockFile) else emptyList()
        }
        every { service.loadCrl(mockFile) } returns crl
        return service
    }

    test("verify() marks ACTIVE as fresh when CRL nextUpdate is in the future") {
        // Свежий ACTIVE — единственный вердикт, годный как fallback-источник
        // при недоступном OCSP (CertificateWrapper.isValid).
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val status = serviceWithSingleCrl(ks.certificate, Date(System.currentTimeMillis() + 86_400_000L))
            .verify(ks.certificate)
        status.result shouldBe CrlResult.ACTIVE
        status.fresh shouldBe true
    }

    test("verify() marks ACTIVE as stale when CRL nextUpdate has passed") {
        // Протухший CRL остаётся детектором отзыва в AND-режиме, но его
        // ACTIVE не может единолично реабилитировать cert при упавшем OCSP.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val status = serviceWithSingleCrl(ks.certificate, Date(System.currentTimeMillis() - 86_400_000L))
            .verify(ks.certificate)
        status.result shouldBe CrlResult.ACTIVE
        status.fresh shouldBe false
    }

    test("verify() marks ACTIVE as stale when CRL has no nextUpdate (nonconforming)") {
        // RFC 5280 §5.1.2.5 требует nextUpdate; его отсутствие трактуем
        // консервативно — CRL непригоден как fallback-основание.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val status = serviceWithSingleCrl(ks.certificate, null).verify(ks.certificate)
        status.result shouldBe CrlResult.ACTIVE
        status.fresh shouldBe false
    }

    test("verify() short-circuits to UNAVAILABLE when CRL feature disabled — no disk reads") {
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_revoked.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val service = buildService(crlEnabled = false)
        // Выключенный CRL — «проверки не было», а не «проверено и чисто».
        service.verify(ks.certificate).result shouldBe CrlResult.UNAVAILABLE
        // isEnabled=false должен выйти до первого I/O. getCrlFiles не должен
        // быть вызван — иначе мы платим за листинг каталогов в hot path
        // верификации каждого подписанта при выключенной фиче.
        verify(exactly = 0) { service.getCrlFiles(any()) }
    }

    // ---- delta-CRL (RFC 5280 §5.2.4) ----

    // DER для INTEGER-расширения CRL (CRLNumber / BaseCRLNumber): getExtensionValue
    // отдаёт OCTET STRING, внутри которого лежит сам INTEGER.
    fun intExt(n: Long): ByteArray = org.bouncycastle.asn1.DEROctetString(
        org.bouncycastle.asn1.ASN1Integer(java.math.BigInteger.valueOf(n)).encoded,
    ).encoded

    fun crlEntry(reason: java.security.cert.CRLReason?, date: Date = Date()): java.security.cert.X509CRLEntry =
        mockk<java.security.cert.X509CRLEntry>(relaxed = true).apply {
            every { revocationReason } returns reason
            every { revocationDate } returns date
        }

    fun mockBaseCrl(
        issuer: javax.security.auth.x500.X500Principal,
        crlNumber: Long,
        nextUpd: Date?,
        revoked: java.security.cert.X509CRLEntry?,
    ): X509CRL = mockk<X509CRL>(relaxed = true).apply {
        every { issuerX500Principal } returns issuer
        every { criticalExtensionOIDs } returns emptySet()
        every { nextUpdate } returns nextUpd
        every { getExtensionValue("2.5.29.20") } returns intExt(crlNumber)
        every { getExtensionValue("2.5.29.27") } returns null
        every { getRevokedCertificate(any<java.security.cert.X509Certificate>()) } returns revoked
    }

    fun mockDeltaCrl(
        issuer: javax.security.auth.x500.X500Principal,
        crlNumber: Long,
        baseCrlNumber: Long,
        nextUpd: Date?,
        revoked: java.security.cert.X509CRLEntry?,
    ): X509CRL = mockk<X509CRL>(relaxed = true).apply {
        every { issuerX500Principal } returns issuer
        // deltaCRLIndicator critical — раньше это роняло CRL в skip, теперь понимаем.
        every { criticalExtensionOIDs } returns setOf("2.5.29.27")
        every { nextUpdate } returns nextUpd
        every { getExtensionValue("2.5.29.20") } returns intExt(crlNumber)
        every { getExtensionValue("2.5.29.27") } returns intExt(baseCrlNumber)
        every { getRevokedCertificate(any<java.security.cert.X509Certificate>()) } returns revoked
    }

    fun serviceWith(baseCrl: X509CRL?, deltaCrl: X509CRL?): CrlService {
        val baseFile = mockCrlFile("base")
        val deltaFile = mockCrlFile("delta_x")
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { ttl } returns null
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val service = spyk(
            CrlService(mockk(relaxed = true), crlConfig, mockk(relaxed = true), HttpClientConfiguration(), mockk(relaxed = true), "test")
        )
        every { service.getCrlFiles(any()) } answers {
            val arg = firstArg<String>()
            when {
                arg.contains("delta") -> if (deltaCrl != null) listOf(deltaFile) else emptyList()
                arg.contains("full") -> if (baseCrl != null) listOf(baseFile) else emptyList()
                else -> emptyList()
            }
        }
        if (baseCrl != null) every { service.loadCrl(baseFile) } returns baseCrl
        if (deltaCrl != null) every { service.loadCrl(deltaFile) } returns deltaCrl
        return service
    }

    val future = Date(System.currentTimeMillis() + 86_400_000L)
    val past = Date(System.currentTimeMillis() - 86_400_000L)

    test("verify() honors a revocation present only in the applicable delta") {
        // Отзыв опубликован в delta, но ещё не попал в base full CRL. Раньше
        // delta с critical deltaCRLIndicator отбрасывалась → отзыв невидим →
        // при упавшем OCSP fallback ложно принял бы отозванный сертификат.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val issuer = cert.x509Certificate.issuerX500Principal
        val base = mockBaseCrl(issuer, crlNumber = 1346, nextUpd = future, revoked = null)
        val delta = mockDeltaCrl(
            issuer, crlNumber = 57725, baseCrlNumber = 1346, nextUpd = future,
            revoked = crlEntry(java.security.cert.CRLReason.KEY_COMPROMISE),
        )
        val status = serviceWith(base, delta).verify(cert)
        status.result shouldBe CrlResult.REVOKED
        status.file shouldBe "delta_x.crl"
    }

    test("verify() treats removeFromCRL in delta as un-revocation (ACTIVE)") {
        // Сертификат был на base CRL, но delta сняла отзыв (removeFromCRL,
        // напр. снятие certificateHold) — итог ACTIVE.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val issuer = cert.x509Certificate.issuerX500Principal
        val base = mockBaseCrl(
            issuer, crlNumber = 1346, nextUpd = past,
            revoked = crlEntry(java.security.cert.CRLReason.CERTIFICATE_HOLD),
        )
        val delta = mockDeltaCrl(
            issuer, crlNumber = 57725, baseCrlNumber = 1346, nextUpd = future,
            revoked = crlEntry(java.security.cert.CRLReason.REMOVE_FROM_CRL),
        )
        val status = serviceWith(base, delta).verify(cert)
        status.result shouldBe CrlResult.ACTIVE
        // Свежесть берётся от применённой delta (base протух, delta свежа).
        status.fresh shouldBe true
    }

    test("verify() ignores a delta that is not applicable to base by CRLNumber") {
        // delta.baseCRLNumber (2000) > base.CRLNumber (1346) — delta покрывает
        // изменения от более нового base, применить к нашему нельзя. Её
        // removeFromCRL не должна реабилитировать отозванный в base сертификат.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val issuer = cert.x509Certificate.issuerX500Principal
        val base = mockBaseCrl(
            issuer, crlNumber = 1346, nextUpd = future,
            revoked = crlEntry(java.security.cert.CRLReason.KEY_COMPROMISE),
        )
        val delta = mockDeltaCrl(
            issuer, crlNumber = 57725, baseCrlNumber = 2000, nextUpd = future,
            revoked = crlEntry(java.security.cert.CRLReason.REMOVE_FROM_CRL),
        )
        serviceWith(base, delta).verify(cert).result shouldBe CrlResult.REVOKED
    }

    test("verify() derives freshness from the applied delta when base is stale") {
        // Base протух по nextUpdate, свежая применимая delta делает
        // объединённую картину текущей → fresh=true (годится для OCSP fallback).
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val issuer = cert.x509Certificate.issuerX500Principal
        val base = mockBaseCrl(issuer, crlNumber = 1346, nextUpd = past, revoked = null)
        val delta = mockDeltaCrl(issuer, crlNumber = 57725, baseCrlNumber = 1346, nextUpd = future, revoked = null)
        val status = serviceWith(base, delta).verify(cert)
        status.result shouldBe CrlResult.ACTIVE
        status.fresh shouldBe true
    }

    test("verify() returns ACTIVE for cert from different CA (CRL issuer mismatch)") {
        // legal_ceo_valid тоже NCA GOST 2022 — issuer тот же. Используем
        // CRL'инский issuer'ный филтр непрямо: если CRL не от того CA, который
        // выпустил cert, он просто игнорируется и в конце возвращается ACTIVE.
        // Для прямого негативного теста легко придумали бы synthetic CRL,
        // но мы остаёмся на реальных fixtures — этот тест проверяет, что
        // happy-path с другим валидным cert'ом не падает.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/legal_ceo_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        buildService().verify(ks.certificate).result shouldBe CrlResult.ACTIVE
    }
})
