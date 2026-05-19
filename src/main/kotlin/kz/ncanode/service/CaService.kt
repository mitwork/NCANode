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
import java.net.http.HttpRequest
import java.net.http.HttpResponse
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

    private val certificates: MutableList<CertificateWrapper> = mutableListOf()

    @Scheduled(fixedRateString = "\${ncanode.ca.ttl}", initialDelay = 0, timeUnit = TimeUnit.MINUTES)
    fun updateCache() {
        if (!caConfiguration.isEnabled) return
        updateCache(false)
    }

    fun updateCache(force: Boolean) {
        synchronized(directoryService) {
            synchronized(certificates) {
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

                // Атомарно подменяем список: с этого момента getRootCertificates()
                // и getRootCertificateFor() видят актуальный набор.
                certificates.clear()
                certificates.addAll(loaded)

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
                            certificates[i] = refreshed
                        }
                    }
                }

                // Чистим orphan-файлы: записи прошлых конфигов, не привязанные
                // ни к одному из текущих URL.
                deleteOrphanCacheFiles(urls.keys)

                log.info("CA certificates cache updated: {} entries", certificates.size)
            }
        }
    }

    private fun deleteOrphanCacheFiles(validKeys: Set<String>) {
        val cacheDir = directoryService.getCachePathFor(CA_CACHE_DIR_NAME) ?: return
        val files = cacheDir.listFiles() ?: return
        for (f in files) {
            if (!f.isFile || !f.name.endsWith(CA_FILE_EXTENSION)) continue
            val stem = f.name.substring(0, f.name.length - CA_FILE_EXTENSION.length)
            if (stem !in validKeys) {
                if (f.delete()) {
                    log.info("Deleted orphan CA cache file: {}", f.name)
                } else {
                    log.warn("Could not delete orphan CA cache file: {}", f)
                }
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
        get() = synchronized(directoryService) {
            synchronized(certificates) {
                if (certificates.isNotEmpty()) {
                    return certificates
                }
                val cacheDir = directoryService.getCachePathFor(CA_CACHE_DIR_NAME) ?: return emptyList()
                val files = cacheDir.listFiles() ?: return emptyList()
                val loaded = files
                    .filter { it.isFile && it.canRead() && it.name.endsWith(CA_FILE_EXTENSION) }
                    .mapNotNull { CertificateWrapper.fromFile(it) }
                certificates.addAll(loaded)
                loaded
            }
        }

    fun download(url: URL, file: File) {
        try {
            val request = HttpRequest.newBuilder(URI(url.toString()))
                .timeout(httpClientConfiguration.requestTimeoutDuration)
                .header("User-Agent", httpClientConfiguration.effectiveUserAgent)
                .GET()
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofByteArray())
            if (response.statusCode() != 200) {
                throw CaException("Cannot download file: $url")
            }
            val body = response.body() ?: throw CaException("Got empty request from: $url")
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
