package kz.ncanode.service

import kz.ncanode.configuration.CaConfiguration
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.exception.CaException
import kz.ncanode.wrapper.CertificateWrapper
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.ExitCodeGenerator
import org.springframework.boot.SpringApplication
import org.springframework.context.ApplicationContext
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.io.File
import java.io.IOException
import java.net.URI
import java.net.URL
import java.net.http.HttpClient
import java.util.concurrent.TimeUnit

/**
 * Сервис для работы с центром сертификации.
 */
@Service
class CaService(
    private val applicationContext: ApplicationContext,
    private val caConfiguration: CaConfiguration,
    private val client: HttpClient,
    private val httpClientConfiguration: HttpClientConfiguration,
    private val directoryService: DirectoryService,
    @param:Qualifier("caCrlService") private val caCrlService: CrlService,
) {

    // Неизменяемый снапшот, публикуемый атомарной заменой ссылки. Читатели
    // (getRootCertificateFor / rootCertificates) берут ссылку и итерируют её
    // БЕЗ блокировки — не видят промежуточного состояния во время updateCache.
    // Раньше это был живой mutableList, а updateCache делал clear()+addAll():
    // lock-free читатель мог поймать ConcurrentModificationException либо
    // транзиентно пустой список → issuer=null → ложный valid:false.
    @Volatile
    private var certificates: List<CertificateWrapper> = emptyList()

    // Монитор сериализации писателей (updateCache + ленивая загрузка в геттере).
    // Отдельный объект: на переприсваиваемом `certificates` синхронизоваться нельзя.
    private val certificatesLock = Any()

    @Scheduled(fixedRateString = "\${ncanode.ca.ttl}", initialDelay = 0, timeUnit = TimeUnit.MINUTES)
    fun updateCache() {
        if (!caConfiguration.isEnabled) return
        updateCache(false)
    }

    fun updateCache(force: Boolean) {
        synchronized(directoryService) {
            synchronized(certificatesLock) {
                val urls = caConfiguration.urlList

                if (urls.isEmpty()) {
                    log.error("CA certificates urls is empty. Please set NCANODE_CA_URL environment variable.")
                    shutdown()
                }

                log.info("Updating CA certificates cache...")

                val ttl = caConfiguration.ttl ?: 0
                val ttlMillis = ttl.toLong() * 60_000L
                val now = System.currentTimeMillis()

                // Pass 1: загружаем актуальные файлы (скачиваем, если протух TTL
                // или нет на диске) и складываем распарсенные сертификаты
                // в in-memory список. Делаем это до проверок ниже, чтобы цепочка
                // issuer-ов была доступна целиком, независимо от порядка URL.
                val loaded = ArrayList<CertificateWrapper>(urls.size)
                val loadedFiles = ArrayList<File>(urls.size)
                val loadedUrls = ArrayList<URL>(urls.size)

                for ((key, url) in urls) {
                    val caFile = File(
                        requireNotNull(directoryService.getCachePathFor(CA_CACHE_DIR_NAME)),
                        key + CA_FILE_EXTENSION,
                    )
                    val stale = caFile.exists() && (now - caFile.lastModified()) > ttlMillis

                    val cert: CertificateWrapper? = if (force || !caFile.exists() || !caFile.canRead() || stale) {
                        downloadCert(url, caFile)
                    } else {
                        CertificateWrapper.fromFile(caFile)
                    }

                    val checked = checkCertForNull(url, cert, caFile) ?: continue
                    loaded.add(checked)
                    loadedFiles.add(caFile)
                    loadedUrls.add(url)
                }

                // Публикуем снапшот атомарной заменой ссылки: с этого момента
                // getRootCertificateFor() (в т.ч. из Pass 2 ниже) и
                // rootCertificates видят актуальную цепочку целиком. Не
                // clear()+addAll() — это давало окно перестройки для lock-free
                // читателей.
                certificates = loaded.toList()

                // Pass 2 может заменить отдельные записи (отозван/протух →
                // перекачка), поэтому работаем на локальной изменяемой копии и
                // публикуем финальный снапшот в конце.
                val revalidated = loaded.toMutableList()

                // Pass 2: для каждого сертификата выставляем issuer (теперь
                // доступен по всему списку) и проверяем срок + CA-CRL.
                // Отозванный → WARN, перекачиваем (может быть свежая замена).
                // Протухший по notAfter → INFO, перекачиваем (NCA мог обновить
                // cert по тому же URL). Если на сервере лежит тот же
                // протухший legacy-корень — следующий проход просто примет
                // его как есть; повторная перекачка раз в TTL допустима.
                for (i in loaded.indices) {
                    val cert = loaded[i]
                    cert.issuerCertificate = getRootCertificateFor(cert)

                    val dateInvalid = !cert.isDateValid()
                    val revoked = caCrlService.verify(cert).result == CrlResult.REVOKED

                    if (revoked) {
                        log.warn("CA certificate from {} is revoked, re-downloading", loadedUrls[i])
                    } else if (dateInvalid) {
                        log.info(
                            "CA certificate from {} is expired (notAfter={}), trying to refresh from server",
                            loadedUrls[i], cert.x509Certificate.notAfter,
                        )
                    }

                    if (dateInvalid || revoked) {
                        val refreshed = downloadCert(loadedUrls[i], loadedFiles[i])
                        if (refreshed != null) {
                            revalidated[i] = refreshed
                        }
                    }
                }

                // Публикуем финальный снапшот (с учётом перекачанных в Pass 2).
                certificates = revalidated.toList()

                // Чистим orphan-файлы: записи прошлых конфигов, не привязанные
                // ни к одному из текущих URL.
                directoryService.deleteOrphans(CA_CACHE_DIR_NAME, CA_FILE_EXTENSION, urls.keys, "CA")

                log.info("CA certificates cache updated: {} entries", certificates.size)
            }
        }
    }

    fun downloadCert(url: URL, file: File): CertificateWrapper? = try {
        log.info("Downloading CA file: {}", url)
        download(url, file)
        log.info("Download complete")
        CertificateWrapper.fromFile(file)
    } catch (e: CaException) {
        log.error(e.message)
        null
    }

    /**
     * Возвращает доверенный корневой сертификат для сертификата ЭЦП, либо null,
     * если в trust-bundle нет подходящего issuer'а.
     */
    fun getRootCertificateFor(cert: CertificateWrapper): CertificateWrapper? {
        if (cert.issuerX500Principal == cert.subjectX500Principal) return null
        return rootCertificates.firstOrNull { root ->
            cert.issuerX500Principal == root.subjectX500Principal && cert.verify(root.publicKey)
        }
    }

    val rootCertificates: List<CertificateWrapper>
        get() {
            // Быстрый lock-free путь: снапшот неизменяем, безопасно отдать и
            // итерировать без блокировки.
            val snapshot = certificates
            if (snapshot.isNotEmpty()) return snapshot
            // Пусто — лениво загружаем с диска под локом (double-checked).
            return synchronized(directoryService) {
                synchronized(certificatesLock) {
                    val current = certificates
                    if (current.isNotEmpty()) {
                        current
                    } else {
                        val cacheDir = directoryService.getCachePathFor(CA_CACHE_DIR_NAME)
                        val loaded = (cacheDir?.listFiles() ?: emptyArray())
                            .filter { it.isFile && it.canRead() && it.name.endsWith(CA_FILE_EXTENSION) }
                            .mapNotNull { CertificateWrapper.fromFile(it) }
                            .toList()
                        certificates = loaded
                        loaded
                    }
                }
            }
        }

    fun download(url: URL, file: File) {
        try {
            val request = httpClientConfiguration.requestBuilder(URI(url.toString()))
                .GET()
                .build()
            // Под тем же потолком, что OCSP/TSP: CA-сертификат — единицы
            // килобайт. Пустое тело больше не превращается в пустой файл на
            // диске — отказ виден сразу, как и при любой другой ошибке загрузки.
            val response = httpClientConfiguration.sendBounded(client, request)
            if (response.statusCode != 200) {
                throw CaException("Cannot download file: $url")
            }
            val body = response.body
            if (body.isEmpty()) throw CaException("Got empty request from: $url")
            file.outputStream().use { out -> out.write(body) }
        } catch (e: IOException) {
            throw CaException("Cannot download file: $url", e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw CaException("Interrupted while downloading: $url", e)
        }
    }

    private fun shutdown() {
        SpringApplication.exit(applicationContext, ExitCodeGenerator { EXIT_CODE })
        System.exit(EXIT_CODE)
    }

    private fun checkCertForNull(url: URL, cert: CertificateWrapper?, caFile: File): CertificateWrapper? {
        if (cert == null) {
            log.error(
                "Cannot open CA certificate from: '{}'. File name: {}",
                url, caFile.absolutePath,
            )
            shutdown()
            return null
        }
        return cert
    }

    companion object {
        private val log = LoggerFactory.getLogger(CaService::class.java)
        private const val EXIT_CODE = 32
        private const val CA_CACHE_DIR_NAME = "ca"
        private const val CA_FILE_EXTENSION = ".cer"
    }
}
