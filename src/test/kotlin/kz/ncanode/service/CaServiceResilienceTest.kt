package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kz.ncanode.TestResources
import kz.ncanode.configuration.CaConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import java.io.File
import java.net.URI
import java.nio.file.Files

/**
 * Недоступность адреса НУЦ не должна ронять сервис.
 *
 * Раньше `CaService` в этом случае звал `System.exit`: один неответивший
 * адрес — и приложение выключено, а при перезапуске всё повторяется, потому
 * что адрес всё ещё молчит. Молчат они регулярно: соединение уходит в пустоту
 * и обрывается по таймауту, следующая попытка проходит мгновенно.
 *
 * Сам факт, что эти тесты доходят до проверок, и есть половина смысла: при
 * прежнем поведении JVM завершилась бы посреди прогона.
 */
class CaServiceResilienceTest : FunSpec({

    fun buildService(cacheDir: File, url: String): CaService {
        val directoryService = mockk<DirectoryService>(relaxed = true)
        every { directoryService.getCachePathFor(any()) } returns cacheDir

        val caConfiguration = mockk<CaConfiguration>(relaxed = true)
        every { caConfiguration.isEnabled } returns true
        every { caConfiguration.ttl } returns 1440
        every { caConfiguration.urlList } returns mapOf("root" to URI(url).toURL())

        val caCrlService = mockk<CrlService>(relaxed = true)
        every { caCrlService.verify(any()) } returns CrlStatus(result = CrlResult.UNAVAILABLE)

        return spyk(
            CaService(
                applicationContext = mockk(relaxed = true),
                caConfiguration = caConfiguration,
                client = mockk(relaxed = true),
                httpClientConfiguration = mockk(relaxed = true),
                directoryService = directoryService,
                caCrlService = caCrlService,
            ),
        )
    }

    test("an unreachable CA address leaves the service running with an empty bundle") {
        val cacheDir = Files.createTempDirectory("ca-cache").toFile().apply { deleteOnExit() }
        val service = buildService(cacheDir, "http://ca.example/root.cer")
        every { service.downloadCert(any(), any()) } returns null

        service.updateCache(true)

        // Пусто — но живы: проверки подписи будут отвечать «издатель не найден»,
        // а не молчанием остановленного сервиса.
        service.rootCertificates.shouldBeEmpty()
    }

    test("a previously cached certificate is used when the download fails") {
        // Устаревший корень лучше отсутствующего: без него не соберётся ни одна
        // цепочка, хотя на диске лежит вчерашняя копия.
        val cacheDir = Files.createTempDirectory("ca-cache").toFile().apply { deleteOnExit() }
        File(cacheDir, "root.cer").writeBytes(TestResources.loadBytes("ca/nca_gost2022_test.cer"))

        val service = buildService(cacheDir, "http://ca.example/root.cer")
        every { service.downloadCert(any(), any()) } returns null

        service.updateCache(true)

        service.rootCertificates.size shouldBe 1
    }
})
