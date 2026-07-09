package kz.ncanode.service

import jakarta.annotation.PostConstruct
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.exception.CrlException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.sha1
import kz.ncanode.wrapper.CertificateWrapper
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.Extension
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.scheduling.TaskScheduler
import org.springframework.scheduling.support.PeriodicTrigger
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.net.URI
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.cert.CRLReason
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509CRLEntry
import java.time.Duration
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal

/**
 * Сервис для реализации механизма проверки сертификатов в CRL.
 */
open class CrlService(
    private val directoryService: DirectoryService,
    private val crlConfiguration: CrlConfiguration,
    private val client: HttpClient,
    private val httpClientConfiguration: HttpClientConfiguration,
    private val taskScheduler: TaskScheduler,
    private val crlServiceType: String,
) {

    /**
     * Каждый CRL-сервис (default vs ca-crl) живёт в собственной поддиректории
     * кэша. Без namespacing'а оба инстанса делят `crl/full` и `crl/delta`,
     * и orphan-cleanup одного удаляет файлы другого как чужие.
     */
    private fun cacheFullDir() = "crl/$crlServiceType/full"
    private fun cacheDeltaDir() = "crl/$crlServiceType/delta"

    /**
     * Кэш для CRL'ей, скачанных по cRLDistributionPoints из самого cert'а
     * (lazy fetch при первой верификации cert'а от неизвестного CA).
     */
    private fun cacheOnDemandDir() = "crl/$crlServiceType/ondemand"

    /**
     * In-memory кэш распарсенных и подпись-верифицированных CRL'ей.
     * Включается через `NCANODE_CRL_CACHE_ENABLED` (по умолчанию true).
     *
     * Без кэша на каждый verify-call делается полный [loadCrl] +
     * `crl.verify(issuerKey)` для каждого файла в каталоге. Для крупных
     * GOST 2015 CRL'ей (десятки MB) это уходит на десятки секунд.
     * С кэшем — миллисекунды (только `isRevoked` lookup).
     *
     * Инвалидация: автоматически по `lastModified` файла. Repeat-verify
     * против того же ключа issuer'а не делается повторно (cmp encoded key
     * bytes).
     */
    private data class CachedCrl(val crl: X509CRL, val fileMtime: Long, val verifiedAgainstKeyEncoded: ByteArray?)
    private val crlMemCache = ConcurrentHashMap<String, CachedCrl>()

    /**
     * Возвращает распарсенный CRL, используя in-memory кэш если включён.
     * При промахе или изменении файла — re-parse, кэшируем без verified-key
     * (signature проверится отдельно).
     */
    private fun loadCachedCrl(file: File): X509CRL {
        if (!crlConfiguration.isCacheEnabled) return loadCrl(file)
        // Без стабильного идентификатора кэшировать нельзя — парсим напрямую.
        // Срабатывает в основном на моках Mockito, где getAbsolutePath() = null.
        val key = file.absolutePath ?: return loadCrl(file)
        val mtime = file.lastModified()
        val cached = crlMemCache[key]
        if (cached != null && cached.fileMtime == mtime) return cached.crl
        val parsed = loadCrl(file)
        crlMemCache[key] = CachedCrl(parsed, mtime, null)
        return parsed
    }

    /**
     * Прогревает in-memory кэш: проходит по всем CRL-файлам в этом
     * cache namespace, парсит каждый и (по возможности) проверяет подпись
     * против issuer-сертификата из переданного CA-bundle'а.
     *
     * Цель — чтобы первый user-verify не платил многосекундную цену парсинга
     * крупных GOST CRL'ей. Прогревается всё что есть на диске; orphan'ы
     * пропускаем тихо.
     *
     * Если cache отключён в конфиге, метод тихо выходит — нет смысла парсить
     * в кэш, который всё равно не используется.
     */
    fun warmCache(caCerts: List<CertificateWrapper>) {
        if (!crlConfiguration.isCacheEnabled) {
            log.debug("CRL cache disabled for '{}', skipping warmup", crlServiceType)
            return
        }

        var parsed = 0
        var sigVerified = 0
        var errors = 0

        for (dir in listOf(cacheFullDir(), cacheDeltaDir(), cacheOnDemandDir())) {
            for (crlFile in getCrlFiles(dir)) {
                try {
                    val crl = loadCachedCrl(crlFile)
                    parsed++

                    val crlIssuer = crl.issuerX500Principal
                    val issuerKey = caCerts.firstOrNull { it.subjectX500Principal == crlIssuer }?.publicKey

                    if (issuerKey != null) {
                        try {
                            verifyCachedSignature(crlFile, crl, issuerKey)
                            sigVerified++
                        } catch (e: GeneralSecurityException) {
                            log.debug(
                                "CRL {} signature verify failed during warmup: {}",
                                crlFile.name, e.message,
                            )
                        }
                    }
                } catch (e: Exception) {
                    errors++
                    log.warn("Failed to warm CRL {}: {}", crlFile.name, e.message)
                }
            }
        }

        log.info(
            "CRL cache warmup for '{}': {} parsed, {} signature-verified, {} errors",
            crlServiceType, parsed, sigVerified, errors,
        )
    }

    /**
     * Криптопроверка подписи CRL ключом issuer'а с кэшированием.
     * Если подпись уже была успешно проверена против того же ключа и
     * файл не менялся — повторно не верифицируется. Throws — как у
     * `X509CRL.verify`, если cert'у нельзя доверять.
     */
    @Throws(GeneralSecurityException::class)
    private fun verifyCachedSignature(file: File, crl: X509CRL, issuerKey: PublicKey) {
        if (!crlConfiguration.isCacheEnabled) {
            crl.verify(issuerKey)
            return
        }
        val key = file.absolutePath
        if (key == null) {
            crl.verify(issuerKey)
            return
        }
        val mtime = file.lastModified()
        val keyEnc = issuerKey.encoded
        val cached = crlMemCache[key]
        if (cached != null
            && cached.fileMtime == mtime
            && cached.verifiedAgainstKeyEncoded != null
            && cached.verifiedAgainstKeyEncoded.contentEquals(keyEnc)
        ) {
            return
        }
        crl.verify(issuerKey)
        crlMemCache[key] = CachedCrl(crl, mtime, keyEnc)
    }

    @PostConstruct
    private fun initializeScheduler() {
        val ttl = crlConfiguration.ttl
        if (ttl == null || ttl < 1) return

        log.info("Initializing '{}' CRL Service...", crlServiceType)
        val trigger = PeriodicTrigger(Duration.ofMinutes(ttl.toLong())).apply {
            setInitialDelay(Duration.ZERO)
            isFixedRate = true
        }
        taskScheduler.schedule({ updateCache(false, crlConfiguration, cacheFullDir()) }, trigger)
    }

    @PostConstruct
    private fun initializeDeltaScheduler() {
        val delta = crlConfiguration.delta ?: return
        val ttl = delta.ttl
        if (ttl == null || ttl < 1) return

        log.info("Initializing '{}' CRL Delta Service...", crlServiceType)
        val trigger = PeriodicTrigger(Duration.ofMinutes(ttl.toLong())).apply {
            setInitialDelay(Duration.ZERO)
            isFixedRate = true
        }
        taskScheduler.schedule({ updateCache(false, delta, cacheDeltaDir()) }, trigger)
    }

    /**
     * Пригодный для проверки CRL этого издателя: распарсен, подпись проверена
     * (если был ключ издателя), critical-расширения приемлемы. `baseCrlNumber`
     * != null ⇒ это delta-CRL (присутствует deltaCRLIndicator). `fresh` —
     * актуален ли CRL по `nextUpdate` на момент проверки.
     */
    private data class UsableCrl(
        val crl: X509CRL,
        val fileName: String,
        val crlNumber: BigInteger?,
        val baseCrlNumber: BigInteger?,
        val fresh: Boolean,
    ) {
        val isDelta: Boolean get() = baseCrlNumber != null
    }

    /**
     * Проверка сертификата в CRL с поддержкой delta-CRL (RFC 5280 §5.2.4).
     *
     * Применяются только CRL'и, выпущенные тем же CA, что и проверяемый
     * сертификат, и с валидной подписью издателя (если у нас есть его
     * публичный ключ). Без этих фильтров серийник сертификата мог бы случайно
     * совпасть с серийником из CRL другого CA, или злонамеренно подложенный
     * CRL ложно отозвал бы валидный сертификат.
     *
     * Delta-CRL (с critical `deltaCRLIndicator`) больше не отбрасывается, а
     * накладывается поверх базового (full) CRL: берётся самый свежий по
     * `CRLNumber` base и применимая к нему delta (`baseCRLNumber <=
     * base.CRLNumber < delta.CRLNumber`). Итог = base ∪ delta, где delta
     * авторитетна для изменений после base, включая `removeFromCRL` (снятие
     * отзыва). Это даёт актуальную картину отзывов между перевыпусками
     * полного CRL — критично для OCSP→CRL fallback'а, который принимает
     * только `fresh`-вердикт (см. [CertificateWrapper.isValid]).
     *
     * Возможные исходы:
     *  - [CrlResult.REVOKED] — серийник отозван по объединённой картине;
     *  - [CrlResult.ACTIVE] — base издателя проверен, серийник не отозван.
     *    `fresh` берётся от применённой delta (если есть), иначе от base —
     *    только `fresh` ACTIVE годится как fallback при недоступном OCSP;
     *  - [CrlResult.UNAVAILABLE] — проверить было нечем (CRL выключен, нет
     *    base CRL этого издателя, все отброшены фильтрами). Это честное
     *    «проверки не было» вместо прежнего фиктивного ACTIVE.
     */
    fun verify(cert: CertificateWrapper): CrlStatus {
        if (!crlConfiguration.isEnabled) {
            return CrlStatus(result = CrlResult.UNAVAILABLE, reason = "CRL check is disabled")
        }

        val certIssuer = cert.issuerX500Principal
        val now = Date()
        // Для self-signed корневых CA issuer и subject совпадают, и подпись
        // на CRL стоит ключом этого же корня — используем его собственный
        // публичный ключ, а не ждём отдельного "issuerCertificate" в trust store.
        val selfSigned = certIssuer == cert.subjectX500Principal
        val issuerKey: PublicKey? = cert.issuerCertificate?.publicKey
            ?: if (selfSigned) cert.publicKey else null

        // On-demand fetch: cert указывает в своём cRLDistributionPoints, откуда
        // качать CRL. Это primary-источник по RFC 5280 §4.2.1.13. Если URL'ы
        // ещё не закэшированы или протухли по TTL — синхронно докачиваем,
        // тогда сбор ниже их подхватит. Конфиг-CRL'и продолжают обслуживаться
        // schedule'ом и тоже остаются в cache (см. updateCache).
        fetchOnDemandCrls(cert)

        // Собираем все пригодные CRL этого издателя из всех кэш-каталогов и
        // делим на base (full) и delta по наличию deltaCRLIndicator.
        val usable = ArrayList<UsableCrl>()
        for (cacheDirectory in listOf(cacheFullDir(), cacheDeltaDir(), cacheOnDemandDir())) {
            for (crlFile in getCrlFiles(cacheDirectory)) {
                loadUsableCrl(crlFile, certIssuer, issuerKey, now)?.let { usable.add(it) }
            }
        }

        // Самый свежий base по CRLNumber (null CRLNumber сортируется как самый
        // старый). Без base полную картину отзывов не построить — UNAVAILABLE.
        val base = usable.filter { !it.isDelta }.maxWithOrNull(compareBy { it.crlNumber })
            ?: return CrlStatus(
                result = CrlResult.UNAVAILABLE,
                reason = "No trusted CRL for certificate issuer in cache",
            )

        // Применимая к base delta с наибольшим CRLNumber (RFC 5280 §5.2.4).
        val delta = usable
            .filter { it.isDelta && isDeltaApplicable(base, it) }
            .maxWithOrNull(compareBy { it.crlNumber })

        val x509 = cert.x509Certificate

        // Delta авторитетна для изменений после base. Её запись про наш серийник
        // либо отзывает (любой reason кроме removeFromCRL), либо снимает отзыв
        // (removeFromCRL — сертификат больше не считается отозванным).
        val deltaEntry = delta?.crl?.getRevokedCertificate(x509)
        if (deltaEntry != null && deltaEntry.revocationReason != CRLReason.REMOVE_FROM_CRL) {
            return revokedStatus(deltaEntry, delta.fileName)
        }
        if (deltaEntry == null) {
            // Delta про серийник молчит — вердикт по base.
            val baseEntry = base.crl.getRevokedCertificate(x509)
            if (baseEntry != null) return revokedStatus(baseEntry, base.fileName)
        }

        // Не отозван → ACTIVE. Свежесть — от применённой delta, иначе от base:
        // объединённая картина «текущая», если текущей является самый свежий
        // применённый источник (RFC 5280 §5.2.4).
        val fresh = if (delta != null) delta.fresh else base.fresh
        return CrlStatus(result = CrlResult.ACTIVE, fresh = fresh)
    }

    /**
     * Применимость delta к base по RFC 5280 §5.2.4: delta покрывает изменения
     * начиная с base не новее нашего (`baseCRLNumber <= base.CRLNumber`) и
     * строго новее нашего base (`base.CRLNumber < delta.CRLNumber`). Без
     * CRLNumber у base либо без baseCRLNumber/CRLNumber у delta упорядочить
     * нельзя — delta консервативно не применяется (работаем на одном base).
     */
    private fun isDeltaApplicable(base: UsableCrl, delta: UsableCrl): Boolean {
        val baseNum = base.crlNumber ?: return false
        val deltaBase = delta.baseCrlNumber ?: return false
        val deltaNum = delta.crlNumber ?: return false
        return deltaBase <= baseNum && baseNum < deltaNum
    }

    private fun revokedStatus(entry: X509CRLEntry, fileName: String): CrlStatus = CrlStatus(
        result = CrlResult.REVOKED,
        file = fileName,
        revocationDate = entry.revocationDate,
        reason = entry.revocationReason?.toString() ?: "",
    )

    /**
     * Загружает CRL-файл и приводит к [UsableCrl], если он пригоден для проверки
     * этого издателя. Иначе — null (пропускаем): чужой issuer, необрабатываемое
     * critical-расширение (кроме deltaCRLIndicator, который мы теперь понимаем),
     * несходящаяся подпись издателя. Протухший по nextUpdate не отбрасывается
     * (для отзывов false negative хуже false positive), но помечается
     * `fresh=false`.
     */
    private fun loadUsableCrl(
        crlFile: File,
        certIssuer: X500Principal,
        issuerKey: PublicKey?,
        now: Date,
    ): UsableCrl? {
        val crl: X509CRL = try {
            loadCachedCrl(crlFile)
        } catch (e: ServerException) {
            log.warn("Skipping unreadable CRL file: {}", crlFile.name)
            return null
        }

        // CRL должен быть выпущен тем же CA, что и проверяемый сертификат.
        if (crl.issuerX500Principal != certIssuer) return null

        // RFC 5280 §5.2: CRL с critical-расширением, которое мы не обрабатываем,
        // использовать нельзя — его охват/семантика неизвестны. Единственное
        // critical-расширение, которое мы понимаем — deltaCRLIndicator (маркер
        // delta-CRL); всё прочее critical (напр. IssuingDistributionPoint) —
        // повод пропустить. BC-флаг hasUnsupportedCriticalExtension не
        // используем — он ненадёжен (см. CertificateWrapper.isValid).
        val unhandledCritical = (crl.criticalExtensionOIDs ?: emptySet()) - SUPPORTED_CRITICAL_CRL_EXTENSIONS
        if (unhandledCritical.isNotEmpty()) {
            log.warn(
                "CRL {} has critical extension(s) {} we do not process — skipping (RFC 5280 §5.2)",
                crlFile.name, unhandledCritical,
            )
            return null
        }

        // RFC 5280 §5.1.2.5: после nextUpdate CRL формально устарел, но мы его
        // не блокируем (отзывы не отменяются). DEBUG — операционно нормально.
        if (crl.nextUpdate != null && crl.nextUpdate.before(now)) {
            log.debug(
                "CRL {} is past its nextUpdate={}, still using for revocation check",
                crlFile.name, crl.nextUpdate,
            )
        }

        // Подпись CRL должна быть подтверждена ключом издателя.
        if (issuerKey != null) {
            try {
                verifyCachedSignature(crlFile, crl, issuerKey)
            } catch (e: GeneralSecurityException) {
                // Это уже реальная проблема — подпись CRL не сходится, либо ключ
                // от другого CA. Такой CRL пропускаем.
                log.warn(
                    "CRL {} signature does not verify against issuer key: {}",
                    crlFile.name, e.message,
                )
                return null
            }
        } else {
            // Issuer'а нет в trust store (типично для легаси-CA). Криптопроверку
            // CRL пропускаем, но сам CRL используем для проверки серийников.
            log.debug(
                "Issuer certificate not available, using CRL {} without signature verification",
                crlFile.name,
            )
        }

        // RFC 5280 §5.1.2.5 требует nextUpdate у conforming CRL; отсутствие поля
        // трактуем консервативно — как несвежий.
        val fresh = crl.nextUpdate != null && !crl.nextUpdate.before(now)
        return UsableCrl(
            crl = crl,
            fileName = crlFile.name,
            crlNumber = readIntegerCrlExtension(crl, Extension.cRLNumber.id),
            baseCrlNumber = readIntegerCrlExtension(crl, Extension.deltaCRLIndicator.id),
            fresh = fresh,
        )
    }

    /**
     * Читает INTEGER-расширение CRL (CRLNumber / BaseCRLNumber) как BigInteger.
     * `getExtensionValue` возвращает DER OCTET STRING, внутри которого лежит сам
     * INTEGER. null, если расширения нет или оно не парсится.
     */
    private fun readIntegerCrlExtension(crl: X509CRL, oid: String): BigInteger? {
        val raw = crl.getExtensionValue(oid) ?: return null
        return try {
            ASN1Integer.getInstance(ASN1OctetString.getInstance(raw).octets).value
        } catch (e: Exception) {
            log.warn("Cannot parse CRL integer extension {}: {}", oid, e.message)
            null
        }
    }

    /**
     * Обновляет кэш CRL.
     *
     * Алгоритм: для каждого настроенного URL считаем, протух ли кэш-файл
     * по TTL; если протух или отсутствует — пробуем скачать новый. Скачивание
     * атомарное (через .tmp + rename), поэтому при сетевой ошибке старый файл
     * остаётся на месте и продолжает использоваться для проверок — окно
     * "нет CRL вообще" не возникает. После загрузки удаляем orphan-файлы
     * (от URL'ов, которых больше нет в конфигурации).
     *
     * Примечание про delta-CRL: загрузка трактует delta как ещё один
     * CRL-эндпоинт (свой URL, свой более частый TTL) — только качает файл.
     * Само наложение delta поверх base по RFC 5280 §5.2.4 (сопоставление
     * CRLNumber / BaseCRLNumber, обработка removeFromCRL) выполняется на
     * этапе проверки — см. [verify].
     */
    @Synchronized
    open fun updateCache(force: Boolean, crlConfiguration: CrlConfiguration, cacheDirectory: String) {
        synchronized(directoryService) {
            val ttl = crlConfiguration.ttl ?: 0
            if (!crlConfiguration.isEnabled || ttl <= 0) return

            log.info("Updating CRL cache for '{}'...", cacheDirectory)
            val currentTime = System.currentTimeMillis()
            val ttlMillis = ttl.toLong() * 60_000L

            var updatedCount = 0

            for ((key, url) in crlConfiguration.urlList) {
                val crlFile = File(
                    requireNotNull(directoryService.getCachePathFor(cacheDirectory)),
                    key + CRL_FILE_EXTENSION,
                )

                val stale = !crlFile.exists()
                    || !crlFile.isFile
                    || !crlFile.canRead()
                    || (currentTime - crlFile.lastModified()) > ttlMillis

                if (!force && !stale) {
                    log.debug("CRL file {} is fresh, keeping", crlFile.name)
                    continue
                }

                downloadCrl(cacheDirectory, url)
                updatedCount++
            }

            // Удаляем orphan-файлы: записи прошлых конфигов, которых больше нет
            // в списке URL'ов.
            deleteOrphanCrlFiles(crlConfiguration.urlList.keys, cacheDirectory)

            if (updatedCount == 0) {
                log.info("Nothing to update in CRL cache for '{}'", cacheDirectory)
            } else {
                log.info("{} files updated in CRL cache for '{}'", updatedCount, cacheDirectory)
            }
        }
    }

    /**
     * Скачивает CRL'и, указанные в `cRLDistributionPoints` cert'а, если они
     * ещё не лежат в кэше или протухли по TTL. Тихий метод — упавший
     * download не пробрасывает наружу (есть логирование внутри downloadCrl),
     * verify() в любом случае попробует использовать имеющийся кэш.
     *
     * URL фильтруются по схеме (только http/https) — defense-in-depth против
     * SSRF через подконтрольный атакующему cert.
     */
    private fun fetchOnDemandCrls(cert: CertificateWrapper) {
        val crlUrls = cert.crlList
        if (crlUrls.isEmpty()) return

        val ttl = crlConfiguration.ttl ?: return
        val ttlMillis = ttl.toLong() * 60_000L
        val now = System.currentTimeMillis()
        val dirName = cacheOnDemandDir()
        val cacheDir = directoryService.getCachePathFor(dirName) ?: return

        for (url in crlUrls) {
            if (!isAllowedCrlScheme(url)) continue
            val fileName = sha1(url.toString()) + CRL_FILE_EXTENSION

            // Дедуп: если URL уже покрывается scheduled-flow'ом (т.е. файл
            // уже есть в config-кэше full или delta), не качаем дубликат
            // в ondemand. Reuse того же файла, что обновляет scheduled-job
            // — экономит диск и убирает удвоенную работу при verify.
            if (isAlreadyInConfigCache(fileName)) {
                log.debug("CRL URL already covered by config cache, skipping on-demand: {}", url)
                continue
            }

            val crlFile = File(cacheDir, fileName)
            val stale = !crlFile.exists()
                || !crlFile.isFile
                || !crlFile.canRead()
                || (now - crlFile.lastModified()) > ttlMillis

            if (!stale) continue

            log.debug("On-demand fetching CRL from cert CRL-DP: {}", url)
            downloadCrl(dirName, url)
        }
    }

    /**
     * Проверяет, лежит ли файл с таким именем в `full` или `delta` каталогах
     * (то есть обслуживается scheduled-update'ом из `NCANODE_CRL_URL` /
     * `NCANODE_CA_CRL_URL`). Если да — on-demand fetch для этого URL не нужен,
     * иначе получим два одинаковых файла в двух каталогах и двойную работу
     * при verify.
     */
    private fun isAlreadyInConfigCache(fileName: String): Boolean =
        fileExistsIn(cacheFullDir(), fileName) || fileExistsIn(cacheDeltaDir(), fileName)

    private fun fileExistsIn(dirName: String, fileName: String): Boolean {
        val dir = directoryService.getCachePathFor(dirName) ?: return false
        return File(dir, fileName).isFile
    }

    private fun isAllowedCrlScheme(url: URL): Boolean {
        val scheme = url.protocol
        val ok = scheme.equals("http", ignoreCase = true) || scheme.equals("https", ignoreCase = true)
        if (!ok) log.warn("Refusing CRL URL with disallowed scheme: {}", url)
        return ok
    }

    private fun deleteOrphanCrlFiles(validKeys: Set<String>, cacheDirName: String) {
        val cacheDir = directoryService.getCachePathFor(cacheDirName) ?: return
        val files = cacheDir.listFiles() ?: return
        for (f in files) {
            if (!f.isFile || !f.name.endsWith(CRL_FILE_EXTENSION)) continue
            val stem = f.name.substring(0, f.name.length - CRL_FILE_EXTENSION.length)
            if (stem !in validKeys) {
                if (f.delete()) {
                    log.info("Deleted orphan CRL cache file: {}", f.name)
                } else {
                    log.warn("Could not delete orphan CRL cache file: {}", f)
                }
            }
        }
    }

    /**
     * Загружает CRL файл.
     */
    fun loadCrl(file: File): X509CRL = try {
        file.inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCRL(input) as X509CRL
        }
    } catch (e: IOException) {
        log.error("Cannot load CRL file \"{}\"", file, e)
        throw ServerException("Cannot load CRL file \"${file.name}\"", e)
    } catch (e: java.security.cert.CRLException) {
        log.error("Cannot load CRL file \"{}\"", file, e)
        throw ServerException("Cannot load CRL file \"${file.name}\"", e)
    } catch (e: CertificateException) {
        log.error("Cannot load CRL file \"{}\"", file, e)
        throw ServerException("Cannot load CRL file \"${file.name}\"", e)
    }

    /**
     * Скачивает CRL файл в директорию.
     */
    fun downloadCrl(cacheDirName: String, url: URL) {
        try {
            val crlUrl = url.toString()
            val crlFileName = sha1(crlUrl) + CRL_FILE_EXTENSION

            log.info("Downloading CRL file from: {}", crlUrl)
            val downloadedFile = download(crlUrl, getCrlCacheFilePathFor(cacheDirName, crlFileName).toPath())
            log.info(
                "CRL file \"{}\" successfully downloaded. Size: {} bytes",
                crlFileName, downloadedFile.length(),
            )
        } catch (e: CrlException) {
            log.error("CRL File download failure", e.cause)
        }
    }

    /**
     * Возвращает список CRL файлов в указанной директории.
     */
    fun getCrlFiles(cacheDirName: String): List<File> {
        val dir = directoryService.getCachePathFor(cacheDirName) ?: return emptyList()
        return (dir.listFiles() ?: emptyArray())
            .filter { it.isFile && it.canRead() && it.name.endsWith(CRL_FILE_EXTENSION) }
    }

    @Throws(CrlException::class)
    private fun download(url: String, path: Path): File {
        // Качаем во временный файл и атомарно подменяем. Если запрос упал
        // или провайдер вернул ошибку — старый CRL на диске остаётся целым,
        // и проверки revocation продолжают работать на нём до следующего цикла.
        val tmpPath = path.resolveSibling(path.fileName.toString() + ".tmp")
        try {
            val request = HttpRequest.newBuilder(URI(url))
                .timeout(httpClientConfiguration.requestTimeoutDuration)
                .header("User-Agent", httpClientConfiguration.effectiveUserAgent)
                .GET()
                .build()
            // ofFile стримит ответ прямо в tmp-файл — для крупных CRL (десятки MB)
            // не держим всё в памяти.
            val response = client.send(request, HttpResponse.BodyHandlers.ofFile(tmpPath))
            val status = response.statusCode()
            if (status != HttpStatus.OK.value()) {
                val location = response.headers().firstValue("location").orElse("<none>")
                throw CrlException("Cannot download file from: $url. Got HTTP status: $status (location=$location)")
            }

            try {
                Files.move(
                    tmpPath, path,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE,
                )
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmpPath, path, StandardCopyOption.REPLACE_EXISTING)
            }

            return path.toFile()
        } catch (e: IOException) {
            throw CrlException(e.message, e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw CrlException("Interrupted while downloading: $url", e)
        } finally {
            // На случай если rename не успел выполниться — чистим хвост.
            try {
                Files.deleteIfExists(tmpPath)
            } catch (e: IOException) {
                // best-effort: оставить файл лучше, чем падать в finally
            }
        }
    }

    private fun getCrlCacheFilePathFor(cacheDirName: String, fileName: String): File =
        File(requireNotNull(directoryService.getCachePathFor(cacheDirName)), fileName)

    companion object {
        private val log = LoggerFactory.getLogger(CrlService::class.java)
        const val CRL_DEFAULT = "default"
        const val CRL_CA = "ca-crl"
        private const val CRL_FILE_EXTENSION = ".crl"

        /**
         * Единственное critical CRL-расширение, которое мы обрабатываем:
         * deltaCRLIndicator (2.5.29.27) — маркер delta-CRL. Любое другое
         * critical-расширение дисквалифицирует CRL (RFC 5280 §5.2).
         */
        private val SUPPORTED_CRITICAL_CRL_EXTENSIONS = setOf(Extension.deltaCRLIndicator.id)
    }
}
