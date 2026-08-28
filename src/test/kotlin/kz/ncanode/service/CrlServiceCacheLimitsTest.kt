package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.configuration.SystemConfiguration
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.crl.CrlIndex
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.wrapper.KalkanWrapper
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpResponse
import java.nio.file.Files

/**
 * Ограничители дискового кэша CRL: потолок размера загрузки и вытеснение
 * on-demand кэша по LRU.
 *
 * Оба нужны из-за нестрогого режима (`NCANODE_CRL_STRICT=false`, дефолт), где
 * URL берётся из `cRLDistributionPoints` присланного сертификата: без потолка
 * такой сертификат заставляет сервер скачать файл произвольного размера, а без
 * вытеснения — накапливать по файлу на каждый новый URL.
 *
 * Здесь используется настоящий [DirectoryService] поверх временного каталога
 * (файлы реально создаются и удаляются); замокан только HTTP-клиент.
 */
class CrlServiceCacheLimitsTest : FunSpec({

    val kalkanWrapper = KalkanWrapper(KalkanProvider())
    val serviceType = "test"
    val onDemandDir = "crl/$serviceType/ondemand"

    fun httpClientReturning(response: HttpResponse<InputStream>): HttpClient =
        mockk<HttpClient>(relaxed = true).apply {
            every { send(any(), any<HttpResponse.BodyHandler<InputStream>>()) } returns response
        }

    fun response(
        body: InputStream,
        status: Int = 200,
        contentLength: Long? = null,
    ): HttpResponse<InputStream> {
        val headers = if (contentLength == null) {
            HttpHeaders.of(emptyMap()) { _, _ -> true }
        } else {
            HttpHeaders.of(mapOf("content-length" to listOf(contentLength.toString()))) { _, _ -> true }
        }
        return mockk<HttpResponse<InputStream>>(relaxed = true).apply {
            every { statusCode() } returns status
            every { body() } returns body
            every { this@apply.headers() } returns headers
        }
    }

    fun service(
        cacheDir: File,
        client: HttpClient = mockk(relaxed = true),
        sizeLimitMb: Int = 64,
        onDemandLimit: Int = 64,
        crlTtl: Int? = null,
    ): CrlService {
        val systemConfiguration = SystemConfiguration().apply { this.cacheDir = cacheDir.absolutePath }
        val crlConfiguration = mockk<CrlConfiguration>(relaxed = true).apply {
            every { isEnabled } returns true
            every { isCacheEnabled } returns false
            every { isStrict } returns false
            every { maxSizeMb } returns sizeLimitMb
            every { onDemandMaxEntries } returns onDemandLimit
            every { ttl } returns crlTtl
            every { urlList } returns emptyMap()
            every { delta } returns null
        }
        return CrlService(
            directoryService = DirectoryService(systemConfiguration),
            crlConfiguration = crlConfiguration,
            client = client,
            httpClientConfiguration = HttpClientConfiguration(),
            taskScheduler = mockk(relaxed = true),
            crlServiceType = serviceType,
        )
    }

    fun tempCacheDir(label: String): File =
        Files.createTempDirectory("ncanode-crl-limits-$label").toFile()

    fun downloadedFile(cacheDir: File, url: String): File =
        File(File(cacheDir, onDemandDir), kz.ncanode.util.sha1(url) + ".crl")

    // ---- потолок размера загрузки ----

    test("stores a CRL that fits within the size limit") {
        val cacheDir = tempCacheDir("fits")
        val payload = TestResources.loadBytes("crl/nca_gost2022_test.crl")
        val url = "http://crl.example.kz/small.crl"

        service(cacheDir, client = httpClientReturning(response(ByteArrayInputStream(payload))))
            .downloadCrl(onDemandDir, URI(url).toURL())

        val stored = downloadedFile(cacheDir, url)
        stored.isFile shouldBe true
        stored.readBytes().contentEquals(payload) shouldBe true
    }

    test("aborts a download whose body grows past the size limit") {
        val cacheDir = tempCacheDir("oversize-body")
        // Сервер не объявил Content-Length — превышение видно только по ходу
        // чтения тела, значит обрывать нужно потоково.
        val body = ByteArrayInputStream(ByteArray(3 * 1024 * 1024))
        val url = "http://crl.example.kz/huge.crl"

        service(cacheDir, client = httpClientReturning(response(body)), sizeLimitMb = 1)
            .downloadCrl(onDemandDir, URI(url).toURL())

        val stored = downloadedFile(cacheDir, url)
        // Ни целевого файла, ни временного: за потолок на диск не попадает ничего.
        stored.exists() shouldBe false
        File(stored.parentFile, stored.name + ".tmp").exists() shouldBe false
    }

    test("refuses an oversized Content-Length without reading the body") {
        val cacheDir = tempCacheDir("oversize-header")
        // Если тело всё-таки будет прочитано — тест упадёт на этом исключении,
        // а не тихо пройдёт.
        val forbidden = object : InputStream() {
            override fun read(): Int = error("body must not be read when Content-Length is over the limit")
            override fun read(b: ByteArray, off: Int, len: Int): Int =
                error("body must not be read when Content-Length is over the limit")
        }
        val url = "http://crl.example.kz/declared-huge.crl"

        service(
            cacheDir,
            client = httpClientReturning(response(forbidden, contentLength = 512L * 1024 * 1024)),
            sizeLimitMb = 64,
        ).downloadCrl(onDemandDir, URI(url).toURL())

        downloadedFile(cacheDir, url).exists() shouldBe false
    }

    test("keeps downloading without a limit when maxSizeMb is not positive") {
        val cacheDir = tempCacheDir("no-limit")
        val payload = TestResources.loadBytes("crl/nca_gost2022_test.crl")
        val url = "http://crl.example.kz/unlimited.crl"

        service(cacheDir, client = httpClientReturning(response(ByteArrayInputStream(payload))), sizeLimitMb = 0)
            .downloadCrl(onDemandDir, URI(url).toURL())

        downloadedFile(cacheDir, url).isFile shouldBe true
    }

    // ---- LRU on-demand кэша ----

    /** Кладёт в on-demand каталог файл с заданным именем, содержимым и mtime. */
    fun putOnDemand(cacheDir: File, name: String, bytes: ByteArray, modifiedAt: Long): File {
        val dir = File(cacheDir, onDemandDir).apply { mkdirs() }
        return File(dir, name).apply {
            writeBytes(bytes)
            setLastModified(modifiedAt)
        }
    }

    test("evicts least recently used on-demand CRLs together with their sidecars") {
        val cacheDir = tempCacheDir("evict")
        val now = System.currentTimeMillis()
        val realCrl = TestResources.loadBytes("crl/nca_gost2022_test.crl")

        // Самый старый — настоящий CRL, у которого есть построенный индекс:
        // проверяем, что вместе с ним уходит и файл-спутник.
        val oldest = putOnDemand(cacheDir, "oldest.crl", realCrl, now - 3 * 60_000)
        CrlIndex.of(oldest)
        val oldestIndex = CrlIndex.indexFileFor(oldest)
        oldestIndex.isFile shouldBe true

        val middle = putOnDemand(cacheDir, "middle.crl", "filler".toByteArray(), now - 2 * 60_000)
        val newest = putOnDemand(cacheDir, "newest.crl", "filler".toByteArray(), now - 60_000)

        service(cacheDir, onDemandLimit = 2).enforceOnDemandLimit()

        oldest.exists() shouldBe false
        oldestIndex.exists() shouldBe false
        middle.isFile shouldBe true
        newest.isFile shouldBe true
    }

    test("spares an on-demand CRL that a verification actually used") {
        val cacheDir = tempCacheDir("spare-used")
        val now = System.currentTimeMillis()

        // Настоящий CRL с самым старым mtime: по одному лишь времени загрузки
        // он ушёл бы первым. Но он пригодится при проверке — и должен остаться.
        val used = putOnDemand(
            cacheDir, "used.crl",
            TestResources.loadBytes("crl/nca_gost2022_test.crl"),
            now - 10 * 60_000,
        )
        val idleOne = putOnDemand(cacheDir, "idle1.crl", "filler".toByteArray(), now - 2 * 60_000)
        val idleTwo = putOnDemand(cacheDir, "idle2.crl", "filler".toByteArray(), now - 60_000)

        val crlService = service(cacheDir, onDemandLimit = 2)
        val certificate = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        ).certificate

        // Сертификат выпущен тем же CA, что и used.crl — CRL пригождается,
        // мусорные файлы отбрасываются как нечитаемые.
        crlService.verify(certificate).result shouldBe CrlResult.ACTIVE

        crlService.enforceOnDemandLimit()

        used.isFile shouldBe true
        // Вытеснен самый давний из непригодившихся.
        idleOne.exists() shouldBe false
        idleTwo.isFile shouldBe true
    }

    test("leaves the on-demand cache alone when the limit is not positive") {
        val cacheDir = tempCacheDir("unlimited")
        val now = System.currentTimeMillis()
        val first = putOnDemand(cacheDir, "a.crl", "filler".toByteArray(), now - 60_000)
        val second = putOnDemand(cacheDir, "b.crl", "filler".toByteArray(), now)

        service(cacheDir, onDemandLimit = 0).enforceOnDemandLimit()

        first.isFile shouldBe true
        second.isFile shouldBe true
    }
})
