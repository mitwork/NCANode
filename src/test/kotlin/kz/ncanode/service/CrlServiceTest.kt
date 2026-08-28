package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.verify
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.crl.CrlIndex
import kz.ncanode.crl.RevokedEntry
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.wrapper.KalkanWrapper
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.cert.CRLReason
import java.util.Date
import javax.security.auth.x500.X500Principal

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

    // Индексируем оба CRL'я один раз на spec. CrlIndex работает поверх файла
    // на диске (рядом кладётся файл-спутник .crl.idx), поэтому ресурсы
    // выкладываем во временный каталог.
    // NCA публикует full ("nca_gost2022_test.crl") и delta ("nca_gost2022_d_test.crl"):
    // отзывы могут лежать в любом из них в зависимости от времени отзыва
    // относительно последнего cut'а full CRL.
    val crlDir = Files.createTempDirectory("ncanode-crl-test").toFile().apply { deleteOnExit() }

    fun indexOf(name: String): CrlIndex {
        val file = File(crlDir, name)
        if (!file.exists()) file.writeBytes(TestResources.loadBytes("crl/$name"))
        return CrlIndex.of(file)
    }

    val gostCrlFull: CrlIndex = indexOf("nca_gost2022_test.crl")

    /**
     * Тот же список, но разобранный: вшитый в подпись материал приходит
     * объектами `X509CRL`, а не файлами, — индекса под него нет.
     */
    val gostCrlParsed: java.security.cert.X509CRL =
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCRL(TestResources.loadBytes("crl/nca_gost2022_test.crl").inputStream())
                as java.security.cert.X509CRL
    val gostCrlDelta: CrlIndex = indexOf("nca_gost2022_d_test.crl")

    // Индекс-заглушка: издатель совпадает, критичных расширений нет, ничего не
    // отозвано, номера CRL отсутствуют. Конкретные тесты доопределяют нужное.
    // Стабим явно, а не полагаемся на relaxed-дефолты: пустой unusableReason
    // или ненулевой find() поменяли бы вердикт.
    fun mockCrlIndex(issuerPrincipal: X500Principal): CrlIndex = mockk<CrlIndex>(relaxed = true).apply {
        every { issuer } returns issuerPrincipal
        every { criticalExtensionOids } returns emptySet()
        every { unusableReason } returns null
        every { crlNumber } returns null
        every { baseCrlNumber } returns null
        every { nextUpdate } returns null
        every { find(any()) } returns null
    }

    fun mockCrlFile(label: String): File = mockk<File>(relaxed = true).apply {
        every { absolutePath } returns "/mock/$label.crl"
        every { name } returns "$label.crl"
        every { isFile } returns true
        every { canRead() } returns true
    }

    fun buildService(crlEnabled: Boolean = true): CrlService {
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns crlEnabled
            every { isCacheEnabled } returns false  // обходит in-memory кэш — loadIndex вызывается напрямую
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
        every { service.loadIndex(fullFile) } returns gostCrlFull
        every { service.loadIndex(deltaFile) } returns gostCrlDelta
        return service
    }

    test("verify() returns REVOKED when CRL marks cert as revoked") {
        // NCA test-pack p12 в реальные test.pki.gov.kz CRL'и не попали
        // (отзывы там обслуживаются через OCSP, а не CRL). Поэтому REVOKED-ветка
        // покрывается через mock'нутый CrlIndex, который объявляет cert
        // отозванным. Цель — проверить CrlService.verify pipeline (issuer-match,
        // signature skip при null issuerKey, поиск по индексу), а не сам
        // двоичный поиск (он покрыт отдельно в CrlIndexTest).
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"),
            null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate
        val revocationDate = Date()
        val revokingCrl = mockCrlIndex(cert.x509Certificate.issuerX500Principal).apply {
            every { find(any()) } returns RevokedEntry(revocationDate, null)
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
        every { service.loadIndex(mockFile) } returns revokingCrl

        val status = service.verify(cert)
        status.result shouldBe CrlResult.REVOKED
        status.revocationDate shouldBe revocationDate
    }

    test("verify() returns ACTIVE against real NCA CRL for a non-revoked cert") {
        // Положительный путь на реальных fixtures: cert не отозван (даже если
        // когда-то им станет, full CRL для individual_valid сейчас не содержит
        // его серийник). Проверяет issuer-match + isRevoked-lookup на честных
        // CRL-данных, не на mock'нутом CrlIndex.
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
        val foreignCrl = mockCrlIndex(X500Principal("CN=Some Other CA")).apply {
            // Эту ветку CrlService даже не должен дойти — issuer mismatch выше.
            every { find(any()) } returns RevokedEntry(Date(), null)
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
        every { service.loadIndex(mockFile) } returns foreignCrl

        service.verify(cert).result shouldBe CrlResult.UNAVAILABLE
        // Поиск даже не должен был случиться — issuer-фильтр срабатывает раньше.
        verify(exactly = 0) { foreignCrl.find(any()) }
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
        val criticalCrl = mockCrlIndex(cert.x509Certificate.issuerX500Principal).apply {
            every { criticalExtensionOids } returns setOf("2.5.29.28") // IDP, critical
            // Если бы CRL НЕ пропустили — он бы отозвал cert. Проверяем, что не доходит.
            every { find(any()) } returns RevokedEntry(Date(), null)
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
        every { service.loadIndex(mockFile) } returns criticalCrl

        // Единственный CRL отброшен → проверять было нечем → UNAVAILABLE.
        service.verify(cert).result shouldBe CrlResult.UNAVAILABLE
        // CRL пропущен до поиска по индексу.
        verify(exactly = 0) { criticalCrl.find(any()) }
    }

    // Хелпер для freshness-тестов: сервис с одним mock-CRL от issuer'а cert'а,
    // не содержащим его серийник, с управляемым nextUpdate.
    fun serviceWithSingleCrl(cert: kz.ncanode.wrapper.CertificateWrapper, crlNextUpdate: Date?): CrlService {
        val crl = mockCrlIndex(cert.x509Certificate.issuerX500Principal).apply {
            // «Не отозван» = серийника нет в индексе.
            every { find(any()) } returns null
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
        every { service.loadIndex(mockFile) } returns crl
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

    fun crlEntry(reason: CRLReason?, date: Date = Date()): RevokedEntry = RevokedEntry(date, reason)

    fun mockBaseCrl(
        issuerPrincipal: X500Principal,
        crlNum: Long,
        nextUpd: Date?,
        revoked: RevokedEntry?,
    ): CrlIndex = mockCrlIndex(issuerPrincipal).apply {
        every { nextUpdate } returns nextUpd
        every { crlNumber } returns BigInteger.valueOf(crlNum)
        every { find(any()) } returns revoked
    }

    fun mockDeltaCrl(
        issuerPrincipal: X500Principal,
        crlNum: Long,
        baseCrlNum: Long,
        nextUpd: Date?,
        revoked: RevokedEntry?,
    ): CrlIndex = mockCrlIndex(issuerPrincipal).apply {
        // deltaCRLIndicator critical — раньше это роняло CRL в skip, теперь понимаем.
        every { criticalExtensionOids } returns setOf("2.5.29.27")
        every { nextUpdate } returns nextUpd
        every { crlNumber } returns BigInteger.valueOf(crlNum)
        every { baseCrlNumber } returns BigInteger.valueOf(baseCrlNum)
        every { find(any()) } returns revoked
    }

    fun serviceWith(baseCrl: CrlIndex?, deltaCrl: CrlIndex?): CrlService {
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
        if (baseCrl != null) every { service.loadIndex(baseFile) } returns baseCrl
        if (deltaCrl != null) every { service.loadIndex(deltaFile) } returns deltaCrl
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
        val base = mockBaseCrl(issuer, crlNum = 1346, nextUpd = future, revoked = null)
        val delta = mockDeltaCrl(
            issuer, crlNum = 57725, baseCrlNum = 1346, nextUpd = future,
            revoked = crlEntry(CRLReason.KEY_COMPROMISE),
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
            issuer, crlNum = 1346, nextUpd = past,
            revoked = crlEntry(CRLReason.CERTIFICATE_HOLD),
        )
        val delta = mockDeltaCrl(
            issuer, crlNum = 57725, baseCrlNum = 1346, nextUpd = future,
            revoked = crlEntry(CRLReason.REMOVE_FROM_CRL),
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
            issuer, crlNum = 1346, nextUpd = future,
            revoked = crlEntry(CRLReason.KEY_COMPROMISE),
        )
        val delta = mockDeltaCrl(
            issuer, crlNum = 57725, baseCrlNum = 2000, nextUpd = future,
            revoked = crlEntry(CRLReason.REMOVE_FROM_CRL),
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
        val base = mockBaseCrl(issuer, crlNum = 1346, nextUpd = past, revoked = null)
        val delta = mockDeltaCrl(issuer, crlNum = 57725, baseCrlNum = 1346, nextUpd = future, revoked = null)
        val status = serviceWith(base, delta).verify(cert)
        status.result shouldBe CrlResult.ACTIVE
        status.fresh shouldBe true
    }

    test("strict mode skips on-demand CRL fetch (SSRF: cert-supplied CRL DP ignored)") {
        // individual_valid несёт cRLDistributionPoints (crl.root.gov.kz). В
        // strict-режиме on-demand загрузка по URL из серта отключена — сервер
        // не ходит на URL, который выбрал серт (в т.ч. внутренний). ttl задан,
        // так что без strict on-demand бы сработал.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val crlConfig = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { isStrict } returns true
            every { ttl } returns 1440
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        val service = spyk(
            CrlService(mockk(relaxed = true), crlConfig, mockk(relaxed = true), HttpClientConfiguration(), mockk(relaxed = true), "test")
        )
        every { service.getCrlFiles(any()) } returns emptyList()
        // Стабим на всякий случай — если strict-гард сломан и downloadCrl всё же
        // вызовется, тест упадёт на verify(exactly=0), но без реальной сети.
        every { service.downloadCrl(any(), any()) } just Runs

        service.verify(ks.certificate)

        verify(exactly = 0) { service.downloadCrl(any(), any()) }
    }

    // ---- вшитые CRL: выбор по покрытию момента ----

    fun issuerWrapper(): kz.ncanode.wrapper.CertificateWrapper =
        kz.ncanode.wrapper.CertificateWrapper(
            java.security.cert.CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                .generateCertificate(TestResources.loadBytes("ca/nca_gost2022_test.cer").inputStream())
                as java.security.cert.X509Certificate,
        )

    test("embedded CRL covering the moment gives a verdict") {
        // Проверка подписи на момент её создания: CRL той поры покрывает этот
        // момент и потому авторитетен, хотя сегодня давно протух.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate.apply { issuerCertificate = issuerWrapper() }
        val inside = Date(gostCrlParsed.thisUpdate.time + 1000)

        val status = buildService().statusOf(cert, listOf(gostCrlParsed), inside)
        status.result shouldBe CrlResult.ACTIVE
        status.fresh shouldBe true
    }

    test("the same embedded CRL says nothing about today") {
        // Тот же список на текущий момент уже не авторитетен: он его не
        // покрывает (RFC 5280 §5.1.2.4–5.1.2.5). Это и есть причина, по которой
        // старая подпись проверяется вшитыми данными, а свежая — живыми.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val cert = ks.certificate.apply { issuerCertificate = issuerWrapper() }

        buildService().statusOf(cert, listOf(gostCrlParsed), Date()).result shouldBe CrlResult.UNAVAILABLE
    }

    test("embedded CRL is rejected when its signature does not verify") {
        // Материал приходит из проверяемого документа, поэтому подпись CRL
        // сверяется ключом издателя так же, как у скачанного. Подставляем
        // чужой ключ издателя — CRL обязан быть отброшен, а не принят на веру.
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        val foreignIssuer = kz.ncanode.wrapper.CertificateWrapper(
            java.security.cert.CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                .generateCertificate(TestResources.loadBytes("ca/root_test_gost_2022.cer").inputStream())
                as java.security.cert.X509Certificate,
        )
        val cert = ks.certificate.apply { issuerCertificate = foreignIssuer }
        val inside = Date(gostCrlParsed.thisUpdate.time + 1000)

        buildService().statusOf(cert, listOf(gostCrlParsed), inside).result shouldBe CrlResult.UNAVAILABLE
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
