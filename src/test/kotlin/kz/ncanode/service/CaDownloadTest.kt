package kz.ncanode.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import kz.ncanode.TestResources
import kz.ncanode.configuration.BoundedResponse
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.exception.CaException
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import kotlin.io.path.createTempDirectory

/**
 * Загрузка сертификата УЦ.
 *
 * Bundle НУЦ — то, чем проверяется вообще всё, а его адреса отвечают не
 * всегда. Здесь проверяется, что неудачная загрузка остаётся неудачной:
 * молчание сервера, ответ не 200 и пустое тело не должны превратиться в
 * пустой или обрезанный файл на диске — такой файл потом читался бы как
 * «сертификат УЦ отсутствует», а причина была бы уже не видна.
 */
class CaDownloadTest : FunSpec({

    TestResources.bootstrap()

    val url = URI("http://pki.gov.kz/cert/nca_gost2022_test.cer").toURL()

    /** Сервис, у которого наружу торчит только HTTP; остальное не участвует. */
    fun serviceReturning(response: () -> BoundedResponse): Pair<CaService, HttpClientConfiguration> {
        val configuration = mockk<HttpClientConfiguration>()
        every { configuration.requestBuilder(any()) } answers { HttpRequest.newBuilder(firstArg<URI>()) }
        every { configuration.sendBounded(any(), any()) } answers { response() }

        val service = CaService(mockk(), mockk(), mockk<HttpClient>(), configuration, mockk(), mockk())
        return service to configuration
    }

    fun tempFile() = createTempDirectory("ca-download").resolve("nca.cer").toFile()

    test("a downloaded certificate is written and parsed") {
        val certificate = TestResources.loadBytes("ca/nca_gost2022_test.cer")
        val (service, _) = serviceReturning { BoundedResponse(200, certificate) }
        val file = tempFile()

        service.downloadCert(url, file).shouldNotBeNull()
        file.readBytes().size shouldBe certificate.size
    }

    test("a response that is not 200 leaves no file behind") {
        val (service, _) = serviceReturning { BoundedResponse(404, "не найдено".toByteArray()) }
        val file = tempFile()

        shouldThrow<CaException> { service.download(url, file) }
        file.exists() shouldBe false
    }

    test("an empty body leaves no file behind") {
        // Иначе на диск лёг бы пустой файл, и следующий проход считал бы его
        // валидным кэшем — отказ стал бы невидимым.
        val (service, _) = serviceReturning { BoundedResponse(200, ByteArray(0)) }
        val file = tempFile()

        shouldThrow<CaException> { service.download(url, file) }
        file.exists() shouldBe false
    }

    test("a network failure becomes a CA error, and downloadCert reports it as no certificate") {
        val (service, _) = serviceReturning { throw IOException("connect timed out") }
        val file = tempFile()

        shouldThrow<CaException> { service.download(url, file) }
        service.downloadCert(url, file).shouldBeNull()
    }

    test("an interrupted download keeps the interruption visible to the caller") {
        // Флаг прерывания снимается при выбросе InterruptedException; если его
        // не восстановить, остановка приложения зависнет на следующем ожидании.
        val (service, _) = serviceReturning { throw InterruptedException("stopping") }
        val file = tempFile()

        try {
            shouldThrow<CaException> { service.download(url, file) }
            Thread.currentThread().isInterrupted shouldBe true
        } finally {
            Thread.interrupted()
        }
    }
})
