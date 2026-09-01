package kz.ncanode.service

import jakarta.annotation.PostConstruct
import kz.ncanode.configuration.HttpClientConfiguration
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.crl.CrlIndex
import kz.ncanode.crl.DerException
import kz.ncanode.crl.RevokedEntry
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.exception.CrlException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.isInternalHost
import kz.ncanode.util.sha1
import kz.ncanode.wrapper.CertificateWrapper
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x509.Extension
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.scheduling.TaskScheduler
import org.springframework.scheduling.support.PeriodicTrigger
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.URI
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpResponse
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.cert.X509CRL
import java.security.cert.CertificateFactory
import java.security.cert.CRLReason
import java.time.Duration
import java.util.Collections
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
     * Кэш открытых CRL-индексов.
     *
     * Сам индекс лежит на диске рядом с CRL и работает через `mmap`, поэтому
     * кэшируется здесь дёшево: в куче — только метаданные, таблица отзывов
     * остаётся file-backed. Прежняя версия держала здесь распарсенный
     * `X509CRL`, а это 243 МБ на одном боевом `nca_gost_2022.crl`.
     *
     * Включается через `NCANODE_CRL_CACHE_ENABLED` (по умолчанию true).
     * Выключенный кэш означает «переоткрывать индекс на каждый verify» — это
     * mmap плюс чтение заголовка, без разбора CRL, но и без запоминания
     * результата проверки подписи.
     *
     * Инвалидация: по `lastModified` файла. Проверка подписи против того же
     * ключа издателя повторно не делается (сравниваем encoded key bytes).
     *
     * Размер ограничен [MEM_CACHE_MAX_ENTRIES] по принципу LRU. Число
     * конфигурационных CRL мало, а on-demand ограничены своим потолком
     * (см. [enforceOnDemandLimit]), так что упереться в этот предел в норме
     * нельзя — он страхует от роста в обход обоих механизмов. Порядок
     * доступа мутируется на чтении, поэтому карта синхронизированная целиком.
     */
    private data class CachedIndex(val index: CrlIndex, val fileMtime: Long, val verifiedAgainstKeyEncoded: ByteArray?)

    private val crlMemCache: MutableMap<String, CachedIndex> = Collections.synchronizedMap(
        object : LinkedHashMap<String, CachedIndex>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: Map.Entry<String, CachedIndex>): Boolean =
                size > MEM_CACHE_MAX_ENTRIES
        },
    )

    /**
     * Когда on-demand CRL последний раз пригодился при проверке (epoch millis).
     * Основание для LRU-вытеснения. Файлы, которых здесь нет (например, после
     * рестарта), упорядочиваются по `lastModified` — то есть по времени
     * загрузки; шкала та же, значения сравнимы напрямую.
     */
    private val onDemandLastUse = ConcurrentHashMap<String, Long>()

    /**
     * Возвращает индекс CRL, используя кэш если он включён. При промахе или
     * изменении файла индекс открывается заново (и при необходимости
     * перестраивается) без запомненного verified-key — подпись проверится
     * отдельно.
     */
    private fun loadCachedIndex(file: File): CrlIndex {
        if (!crlConfiguration.isCacheEnabled) return loadIndex(file)
        // Без стабильного идентификатора кэшировать нельзя — открываем напрямую.
        // Срабатывает в основном на моках, где getAbsolutePath() = null.
        val key = file.absolutePath ?: return loadIndex(file)
        val mtime = file.lastModified()
        val cached = crlMemCache[key]
        if (cached != null && cached.fileMtime == mtime) return cached.index
        val index = loadIndex(file)
        crlMemCache[key] = CachedIndex(index, mtime, null)
        return index
    }

    /**
     * Прогревает кэш: проходит по всем CRL-файлам в этом cache namespace,
     * открывает индекс каждого (строя его, если файла-спутника ещё нет или он
     * устарел) и по возможности проверяет подпись против issuer-сертификата из
     * переданного CA-bundle'а.
     *
     * Цель — чтобы первый user-verify не платил за построение индекса крупного
     * CRL. После первого запуска индексы лежат на диске, и прогрев сводится к
     * их открытию. Прогревается всё что есть на диске; orphan'ы пропускаем тихо.
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
                    val index = loadCachedIndex(crlFile)
                    parsed++

                    val issuerKey = caCerts.firstOrNull { it.subjectX500Principal == index.issuer }?.publicKey

                    if (issuerKey != null) {
                        try {
                            verifyCachedSignature(crlFile, index, issuerKey)
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
    private fun verifyCachedSignature(file: File, index: CrlIndex, issuerKey: PublicKey) {
        if (!crlConfiguration.isCacheEnabled) {
            index.verifySignature(issuerKey)
            return
        }
        val key = file.absolutePath
        if (key == null) {
            index.verifySignature(issuerKey)
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
        index.verifySignature(issuerKey)
        crlMemCache[key] = CachedIndex(index, mtime, keyEnc)
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
        /**
         * Поиск записи об отзыве. Функцией, а не конкретным типом: из кэша
         * записи ищет mmap-индекс, а у материала, вшитого в подпись, на руках
         * разобранный `X509CRL` — вердикт для обоих должен быть один.
         */
        val find: (BigInteger) -> RevokedEntry?,
        /** Файл в кэше; у вшитого материала его нет. */
        val sourceFile: File?,
        val fileName: String,
        val crlNumber: BigInteger?,
        val baseCrlNumber: BigInteger?,
        /** Список действует на момент проверки — от этого зависит fallback с OCSP. */
        val fresh: Boolean,
        /** Список свидетельствует о состоянии на момент проверки — см. [authoritativeAt]. */
        val authoritative: Boolean = fresh,
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

        val (base, delta) = selectCrls(certIssuer, issuerKey, now)
        // Без base полную картину отзывов не построить — UNAVAILABLE.
        if (base == null) {
            return CrlStatus(
                result = CrlResult.UNAVAILABLE,
                reason = "No trusted CRL for certificate issuer in cache",
            )
        }

        return verdict(base, delta, cert)
    }

    /**
     * Вердикт по отобранным base и delta. Общий для проверки по кэшу и по
     * материалу, вшитому в подпись: одни и те же данные не должны давать
     * разный ответ в зависимости от того, откуда они пришли.
     */
    private fun verdict(base: UsableCrl, delta: UsableCrl?, cert: CertificateWrapper): CrlStatus {
        val serial = cert.x509Certificate.serialNumber

        // Delta авторитетна для изменений после base. Её запись про наш серийник
        // либо отзывает (любой reason кроме removeFromCRL), либо снимает отзыв
        // (removeFromCRL — сертификат больше не считается отозванным).
        val deltaEntry = delta?.find?.invoke(serial)
        if (deltaEntry != null && deltaEntry.reason != CRLReason.REMOVE_FROM_CRL) {
            return revokedStatus(deltaEntry, delta.fileName)
        }
        if (deltaEntry == null) {
            // Delta про серийник молчит — вердикт по base.
            val baseEntry = base.find(serial)
            if (baseEntry != null) return revokedStatus(baseEntry, base.fileName)
        }

        // Не отозван → ACTIVE. Свежесть — от применённой delta, иначе от base:
        // объединённая картина «текущая», если текущей является самый свежий
        // применённый источник (RFC 5280 §5.2.4).
        val fresh = if (delta != null) delta.fresh else base.fresh
        return CrlStatus(result = CrlResult.ACTIVE, fresh = fresh)
    }

    /**
     * Отбирает пригодные CRL издателя из кэша: самый свежий base по `CRLNumber`
     * и применимую к нему delta (RFC 5280 §5.2.4).
     *
     * Общий для [verify] и [collectCrls] — иначе проверка и встраивание могли
     * бы опираться на разные наборы CRL, и подпись уровня LT содержала бы не
     * тот материал, по которому мы сами выносим вердикт.
     */
    private fun selectCrls(
        certIssuer: X500Principal,
        issuerKey: PublicKey?,
        now: Date,
    ): Pair<UsableCrl?, UsableCrl?> {
        val usable = ArrayList<UsableCrl>()
        val onDemandDir = cacheOnDemandDir()
        for (cacheDirectory in listOf(cacheFullDir(), cacheDeltaDir(), onDemandDir)) {
            for (crlFile in getCrlFiles(cacheDirectory)) {
                loadUsableCrl(crlFile, certIssuer, issuerKey, now)?.let {
                    // Отмечаем именно пригодившийся CRL: тот, что не подошёл ни
                    // одному издателю, так и остаётся кандидатом на вытеснение.
                    if (cacheDirectory == onDemandDir) {
                        onDemandLastUse[crlFile.absolutePath] = System.currentTimeMillis()
                    }
                    usable.add(it)
                }
            }
        }

        val base = usable.filter { !it.isDelta }.maxWithOrNull(compareBy { it.crlNumber })
            ?: return null to null
        val delta = usable
            .filter { it.isDelta && isDeltaApplicable(base, it) }
            .maxWithOrNull(compareBy { it.crlNumber })
        return base to delta
    }

    /**
     * CRL'и, применимые к издателю [cert] — для встраивания в подпись уровня
     * LT. Отбор тот же, что при проверке; пустой список означает, что
     * встраивать нечего.
     */
    fun collectCrls(cert: CertificateWrapper): List<X509CRL> {
        if (!crlConfiguration.isEnabled) return emptyList()

        val certIssuer = cert.issuerX500Principal
        val selfSigned = certIssuer == cert.subjectX500Principal
        val issuerKey: PublicKey? = cert.issuerCertificate?.publicKey
            ?: if (selfSigned) cert.publicKey else null

        fetchOnDemandCrls(cert)
        val (base, delta) = selectCrls(certIssuer, issuerKey, Date())
        return listOfNotNull(base, delta).mapNotNull { readCrl(it.sourceFile) }
    }

    /** Разбирает файл кэша в `X509CRL` — только для встраивания в подпись. */
    private fun readCrl(file: File?): X509CRL? {
        if (file == null) return null
        return try {
            file.inputStream().use {
                CertificateFactory.getInstance("X.509").generateCRL(it) as X509CRL
            }
        } catch (e: Exception) {
            log.warn("Cannot read CRL {} for embedding: {}", file.name, e.message)
            null
        }
    }

    /**
     * Вердикт по CRL, вшитым в подпись, на момент [at].
     *
     * Два принципиальных отличия от проверки по кэшу. Момент — не «сейчас», а
     * время, на которое проверяется подпись; годность списка относительно него
     * решает [authoritativeAt]. И материал пришёл из проверяемого документа,
     * поэтому подпись каждого CRL проверяется ключом издателя ровно так же, как
     * у скачанного: иначе мы доверяли бы тому, что нам прислали.
     */
    fun statusOf(cert: CertificateWrapper, crls: List<X509CRL>, at: Date): CrlStatus {
        if (crls.isEmpty()) {
            return CrlStatus(result = CrlResult.UNAVAILABLE, reason = "No embedded CRL")
        }

        val certIssuer = cert.issuerX500Principal
        val selfSigned = certIssuer == cert.subjectX500Principal
        val issuerKey: PublicKey? = cert.issuerCertificate?.publicKey
            ?: if (selfSigned) cert.publicKey else null

        val usable = crls.mapIndexedNotNull { index, crl ->
            embeddedCrl(crl, "embedded#${'$'}{index + 1}", certIssuer, issuerKey, at, cert.x509Certificate.notAfter)
        }
        val base = usable.filter { !it.isDelta }.maxWithOrNull(compareBy { it.crlNumber })
            ?: return CrlStatus(
                result = CrlResult.UNAVAILABLE,
                reason = "No embedded CRL covering the validation time",
            )
        val delta = usable
            .filter { it.isDelta && isDeltaApplicable(base, it) }
            .maxWithOrNull(compareBy { it.crlNumber })

        val status = verdict(base, delta, cert)
        // ACTIVE от списка, который о моменте проверки ничего не говорит, — не
        // свидетельство. А вот REVOKED остаётся в силе: отзывы не отменяются, и
        // запись о нём говорит сама за себя. Без этого различия вшитые данные
        // перебивали бы живые при проверке «на сейчас», хотя устарели.
        val authoritative = if (delta != null) delta.authoritative else base.authoritative
        return if (status.result == CrlResult.ACTIVE && !authoritative) {
            CrlStatus(
                result = CrlResult.UNAVAILABLE,
                reason = "Embedded CRL does not cover the validation time",
            )
        } else {
            status
        }
    }

    /**
     * Приводит вшитый в подпись CRL к [UsableCrl]. Фильтры те же, что у
     * кэшированного: чужой издатель, непонятое critical-расширение,
     * несходящаяся подпись — списком не пользуемся.
     */
    private fun embeddedCrl(
        crl: X509CRL,
        name: String,
        certIssuer: X500Principal,
        issuerKey: PublicKey?,
        at: Date,
        certNotAfter: Date,
    ): UsableCrl? {
        if (crl.issuerX500Principal != certIssuer) return null

        val unhandledCritical = (crl.criticalExtensionOIDs ?: emptySet()) - SUPPORTED_CRITICAL_CRL_EXTENSIONS
        if (unhandledCritical.isNotEmpty()) {
            log.warn("Embedded CRL {} has critical extension(s) {} we do not process — skipping", name, unhandledCritical)
            return null
        }

        if (issuerKey != null) {
            try {
                crl.verify(issuerKey)
            } catch (e: GeneralSecurityException) {
                log.warn("Embedded CRL {} signature does not verify against issuer key: {}", name, e.message)
                return null
            }
        }

        val fresh = crl.nextUpdate != null && !crl.nextUpdate.before(at) && !crl.thisUpdate.after(at)
        return UsableCrl(
            find = { serial ->
                crl.revokedCertificates
                    ?.firstOrNull { it.serialNumber == serial }
                    ?.let { RevokedEntry(it.revocationDate, it.revocationReason) }
            },
            sourceFile = null,
            fileName = name,
            crlNumber = readIntegerCrlExtension(crl, Extension.cRLNumber.id),
            baseCrlNumber = readIntegerCrlExtension(crl, Extension.deltaCRLIndicator.id),
            fresh = fresh,
            authoritative = authoritativeAt(crl.thisUpdate, crl.nextUpdate, at, certNotAfter),
        )
    }

    /**
     * Читает INTEGER-расширение разобранного CRL (CRLNumber / BaseCRLNumber).
     * У кэшированных списков эти числа берутся из индекса, а у вшитых в
     * подпись — только отсюда. `null`, если расширения нет или оно не парсится.
     */
    private fun readIntegerCrlExtension(crl: X509CRL, oid: String): BigInteger? {
        val raw = crl.getExtensionValue(oid) ?: return null
        return try {
            val octets = (ASN1Primitive.fromByteArray(raw) as ASN1OctetString).octets
            (ASN1Primitive.fromByteArray(octets) as ASN1Integer).value
        } catch (e: Exception) {
            log.warn("Cannot parse CRL integer extension {}: {}", oid, e.message)
            null
        }
    }

    /**
     * Свидетельствуют ли данные об отзыве о состоянии сертификата на момент [at].
     *
     * Два случая, и оба нужны:
     *
     *  - интервал `[thisUpdate, nextUpdate]` накрывает [at] — обычная проверка
     *    «сейчас» и проверка старой подписи по вшитому в неё материалу;
     *  - данные выпущены **позже** [at], но пока сертификат ещё действовал.
     *    Отзыв необратим и попадает в списки с датой: если бы сертификат
     *    отозвали до [at], более поздние данные показали бы это с
     *    `revocationDate ≤ at`. Поэтому свежие данные свидетельствуют и о
     *    прошлом — на этом стоит повышение уровня подписи (ETSI EN 319 102-1).
     *
     * Граница у второго случая принципиальна: после истечения сертификата
     * издатель вправе убрать запись о нём из списка (RFC 5280 §5), и тогда
     * отозванный сертификат выглядел бы добропорядочным.
     */
    private fun authoritativeAt(
        thisUpdate: Date?,
        nextUpdate: Date?,
        at: Date,
        certNotAfter: Date?,
    ): Boolean {
        if (thisUpdate == null) return false
        val covers = nextUpdate != null && !nextUpdate.before(at) && !thisUpdate.after(at)
        if (covers) return true

        val issuedAfter = !thisUpdate.before(at)
        val certificateStillValid = certNotAfter == null || !thisUpdate.after(certNotAfter)
        return issuedAfter && certificateStillValid
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

    private fun revokedStatus(entry: RevokedEntry, fileName: String): CrlStatus = CrlStatus(
        result = CrlResult.REVOKED,
        file = fileName,
        revocationDate = entry.revocationDate,
        reason = entry.reason?.toString() ?: "",
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
        val index: CrlIndex = try {
            loadCachedIndex(crlFile)
        } catch (e: ServerException) {
            log.warn("Skipping unreadable CRL file: {}", crlFile.name)
            return null
        }
        // CRL должен быть выпущен тем же CA, что и проверяемый сертификат.
        if (index.issuer != certIssuer) return null

        // Indirect CRL либо запись с непонятым critical-расширением: записи
        // нельзя сопоставлять по одному лишь серийнику (RFC 5280 §5.3).
        index.unusableReason?.let { reason ->
            log.warn("CRL {} is not usable for revocation checking ({}) — skipping", crlFile.name, reason)
            return null
        }

        // RFC 5280 §5.2: CRL с critical-расширением, которое мы не обрабатываем,
        // использовать нельзя — его охват/семантика неизвестны. Единственное
        // critical-расширение, которое мы понимаем — deltaCRLIndicator (маркер
        // delta-CRL); всё прочее critical (напр. IssuingDistributionPoint) —
        // повод пропустить. BC-флаг hasUnsupportedCriticalExtension не
        // используем — он ненадёжен (см. CertificateWrapper.isValid).
        val unhandledCritical = index.criticalExtensionOids - SUPPORTED_CRITICAL_CRL_EXTENSIONS
        if (unhandledCritical.isNotEmpty()) {
            log.warn(
                "CRL {} has critical extension(s) {} we do not process — skipping (RFC 5280 §5.2)",
                crlFile.name, unhandledCritical,
            )
            return null
        }

        // RFC 5280 §5.1.2.5: после nextUpdate CRL формально устарел, но мы его
        // не блокируем (отзывы не отменяются). DEBUG — операционно нормально.
        val nextUpdate = index.nextUpdate
        if (nextUpdate != null && nextUpdate.before(now)) {
            log.debug(
                "CRL {} is past its nextUpdate={}, still using for revocation check",
                crlFile.name, nextUpdate,
            )
        }

        // Подпись CRL должна быть подтверждена ключом издателя.
        if (issuerKey != null) {
            try {
                verifyCachedSignature(crlFile, index, issuerKey)
            } catch (e: GeneralSecurityException) {
                // Это уже реальная проблема — подпись CRL не сходится, либо ключ
                // от другого CA. Такой CRL пропускаем.
                log.warn("CRL {} signature does not verify against issuer key: {}", crlFile.name, e.message)
                return null
            }
        } else {
            // Issuer'а нет в trust store (типично для легаси-CA). Криптопроверку
            // CRL пропускаем, но сам CRL используем для проверки серийников.
            log.debug("Issuer certificate not available, using CRL {} without signature verification", crlFile.name)
        }

        // RFC 5280 §5.1.2.5 требует nextUpdate у conforming CRL; отсутствие поля
        // трактуем консервативно — как несвежий.
        val fresh = nextUpdate != null && !nextUpdate.before(now)
        return UsableCrl(
            find = index::find,
            sourceFile = crlFile,
            fileName = crlFile.name,
            crlNumber = index.crlNumber,
            baseCrlNumber = index.baseCrlNumber,
            fresh = fresh,
        )
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

                downloadCrlWithRetries(cacheDirectory, url, crlConfiguration.retries)
                updatedCount++
            }

            // Удаляем orphan-файлы: записи прошлых конфигов, которых больше нет
            // в списке URL'ов.
            directoryService.deleteOrphans(cacheDirectory, CRL_FILE_EXTENSION, crlConfiguration.urlList.keys, "CRL")
            // Файл-спутник живёт рядом с CRL и должен уходить вместе с ним.
            directoryService.deleteOrphans(
                cacheDirectory, CrlIndex.INDEX_EXTENSION, crlConfiguration.urlList.keys, "CRL index",
            )

            if (updatedCount == 0) {
                log.info("Nothing to update in CRL cache for '{}'", cacheDirectory)
            } else {
                log.info("{} files updated in CRL cache for '{}'", updatedCount, cacheDirectory)
            }

            // Периодическая уборка on-demand кэша. Без неё уже разросшийся
            // кэш ужался бы только при следующей загрузке по CRL DP — на
            // инстансе, который их больше не получает, никогда.
            enforceOnDemandLimit()
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
        // Strict-режим (SSRF): on-demand загрузка по CRL DP серта отключена —
        // используем только scheduled конфиг-CRL. Серт не может заставить нас
        // скачать CRL с произвольного (внутреннего) URL.
        if (crlConfiguration.isStrict) return

        val crlUrls = cert.crlList
        if (crlUrls.isEmpty()) return

        val ttl = crlConfiguration.ttl ?: return
        val ttlMillis = ttl.toLong() * 60_000L
        val now = System.currentTimeMillis()
        val dirName = cacheOnDemandDir()
        val cacheDir = directoryService.getCachePathFor(dirName) ?: return
        var fetched = false

        for (url in crlUrls) {
            // Минимальный SSRF-барьер: URL из серта не должен указывать на
            // loopback/link-local (cloud-metadata) — см. isInternalHost.
            if (!isAllowedCrlScheme(url) || isInternalHost(url)) continue
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
            fetched = true
        }

        // Кэш пополняется URL'ами из присланных сертификатов, то есть растёт
        // ровно настолько, насколько разнообразны запросы. Держим его в рамках.
        if (fetched) enforceOnDemandLimit()
    }

    /**
     * Ограничивает размер on-demand кэша [CrlConfiguration.onDemandMaxEntries]
     * файлами, вытесняя реже всего использованные вместе с их
     * файлами-спутниками и записями in-memory кэша.
     *
     * «Реже всего использованный» — по последнему успешному применению в
     * [verify]; для файлов, которые ни разу не пригодились в этом процессе
     * (в том числе оставшихся от прошлого запуска), берётся время загрузки.
     * Так первыми уходят CRL, скачанные по CRL DP из чужих сертификатов и
     * никому не пригодившиеся.
     *
     * Публичный и синхронизированный: вызывается после загрузок, сериализуется
     * с [updateCache], чтобы не удалять файл, который прямо сейчас пишется.
     */
    @Synchronized
    open fun enforceOnDemandLimit() {
        val limit = crlConfiguration.onDemandMaxEntries
        if (limit <= 0) return

        val files = getCrlFiles(cacheOnDemandDir())

        // Подчищаем хвосты учёта от файлов, которых уже нет на диске.
        val present = files.mapTo(HashSet()) { it.absolutePath }
        onDemandLastUse.keys.retainAll(present)

        if (files.size <= limit) return

        val victims = files.sortedBy { lastUseOf(it) }.take(files.size - limit)
        log.info(
            "On-demand CRL cache holds {} files, limit is {} — evicting {} least recently used",
            files.size, limit, victims.size,
        )
        for (victim in victims) evictOnDemandCrl(victim)
    }

    private fun lastUseOf(file: File): Long =
        maxOf(onDemandLastUse[file.absolutePath] ?: 0L, file.lastModified())

    private fun evictOnDemandCrl(file: File) {
        val indexFile = CrlIndex.indexFileFor(file)
        crlMemCache.remove(file.absolutePath)
        onDemandLastUse.remove(file.absolutePath)

        if (file.delete()) {
            log.debug("Evicted on-demand CRL {}", file.name)
        } else {
            log.warn("Could not evict on-demand CRL {}", file)
        }
        if (indexFile.isFile && !indexFile.delete()) {
            log.warn("Could not delete index of evicted CRL {}", indexFile)
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

    /**
     * Открывает индекс CRL-файла, строя его при первом обращении или после
     * обновления файла. Дорогая часть (обход CRL) выполняется только при
     * перестроении; дальше это mmap готового файла-спутника.
     */
    open fun loadIndex(file: File): CrlIndex = try {
        CrlIndex.of(file)
    } catch (e: IOException) {
        log.error("Cannot load CRL file \"{}\"", file, e)
        throw ServerException("Cannot load CRL file \"" + file.name + "\"", e)
    } catch (e: DerException) {
        log.error("Cannot parse CRL file \"{}\"", file, e)
        throw ServerException("Cannot parse CRL file \"" + file.name + "\"", e)
    }

    /**
     * Скачивает CRL файл в директорию. Одна попытка — для загрузки по ссылке
     * из сертификата, которая идёт внутри проверки подписи.
     */
    fun downloadCrl(cacheDirName: String, url: URL) {
        try {
            downloadCrlOrThrow(cacheDirName, url)
        } catch (e: CrlException) {
            log.error("CRL File download failure", e.cause)
        }
    }

    /**
     * То же, но с повторами — для планового обновления кэша.
     *
     * Хост НУЦ через раз не отвечает вовсе: соединение уходит в пустоту и
     * обрывается по таймауту, тогда как следующая попытка проходит за
     * миллисекунды. Расплата за единственную неудачу непропорциональна —
     * список остаётся прежним до следующего срабатывания расписания, то есть
     * на весь TTL (у CA-CRL это сутки).
     *
     * Повторяем только здесь: загрузку по ссылке из сертификата ждёт клиент,
     * и лишние попытки растянули бы ему ответ.
     */
    fun downloadCrlWithRetries(cacheDirName: String, url: URL, attempts: Int) {
        val total = attempts.coerceAtLeast(1)
        for (attempt in 1..total) {
            try {
                downloadCrlOrThrow(cacheDirName, url)
                return
            } catch (e: CrlException) {
                if (attempt == total) {
                    log.error("CRL File download failure", e.cause)
                    return
                }
                log.warn(
                    "CRL download from {} failed (attempt {} of {}): {} — retrying",
                    url, attempt, total, e.cause?.message ?: e.message,
                )
                if (!pauseBeforeRetry(attempt)) return
            }
        }
    }

    /** Пауза перед повтором. `false` — нас остановили, повторять не нужно. */
    private fun pauseBeforeRetry(attempt: Int): Boolean = try {
        Thread.sleep(RETRY_BACKOFF_MS * attempt)
        true
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    internal open fun downloadCrlOrThrow(cacheDirName: String, url: URL) {
        val crlUrl = url.toString()
        val crlFileName = sha1(crlUrl) + CRL_FILE_EXTENSION

        log.info("Downloading CRL file from: {}", crlUrl)
        val downloadedFile = download(crlUrl, getCrlCacheFilePathFor(cacheDirName, crlFileName).toPath())
        log.info(
            "CRL file \"{}\" successfully downloaded. Size: {} bytes",
            crlFileName, downloadedFile.length(),
        )
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
        val maxBytes = maxDownloadBytes()
        try {
            val request = httpClientConfiguration.requestBuilder(URI(url))
                .GET()
                .build()
            // ofInputStream, а не ofFile: тело копируем сами, чтобы оборвать
            // загрузку на превышении потолка. ofFile принял бы файл любого
            // размера, а URL в нестрогом режиме приходит из чужого сертификата.
            // Память при этом всё так же не растёт — копируем буфером.
            val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())
            response.body().use { body ->
                val status = response.statusCode()
                if (status != HttpStatus.OK.value()) {
                    val location = response.headers().firstValue("location").orElse("<none>")
                    throw CrlException(
                        "Cannot download file from: $url. Got HTTP status: $status (location=$location)",
                    )
                }

                // Если сервер объявил размер — отказываемся, не читая тело.
                val declared = response.headers().firstValueAsLong(CONTENT_LENGTH_HEADER).orElse(-1L)
                if (maxBytes > 0 && declared > maxBytes) {
                    throw CrlException(
                        "CRL at $url declares $declared bytes, over the $maxBytes byte limit " +
                            "(ncanode.crl.maxSizeMb)",
                    )
                }

                Files.newOutputStream(tmpPath).use { output -> copyLimited(body, output, maxBytes, url) }
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

    /** Потолок загрузки в байтах; ноль или меньше — без ограничения. */
    private fun maxDownloadBytes(): Long {
        val megabytes = crlConfiguration.maxSizeMb
        return if (megabytes <= 0) 0L else megabytes.toLong() * 1024L * 1024L
    }

    /**
     * Копирует тело ответа, обрывая загрузку на превышении [maxBytes].
     * Проверка идёт до записи очередного блока, так что за потолок на диск
     * не попадает ничего.
     */
    @Throws(CrlException::class, IOException::class)
    private fun copyLimited(input: InputStream, output: OutputStream, maxBytes: Long, url: String): Long {
        val buffer = ByteArray(DOWNLOAD_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (maxBytes > 0 && total > maxBytes) {
                throw CrlException("CRL at $url exceeds the $maxBytes byte limit (ncanode.crl.maxSizeMb)")
            }
            output.write(buffer, 0, read)
        }
        return total
    }

    companion object {
        /** База паузы между попытками: 1-я — 1 с, 2-я — 2 с. */
        private const val RETRY_BACKOFF_MS = 1000L

        private val log = LoggerFactory.getLogger(CrlService::class.java)
        const val CRL_DEFAULT = "default"
        const val CRL_CA = "ca-crl"
        private const val CRL_FILE_EXTENSION = ".crl"
        private const val CONTENT_LENGTH_HEADER = "content-length"
        private const val DOWNLOAD_BUFFER_SIZE = 64 * 1024

        /** Потолок числа открытых индексов в памяти, см. `crlMemCache`. */
        private const val MEM_CACHE_MAX_ENTRIES = 256

        /**
         * Единственное critical CRL-расширение, которое мы обрабатываем:
         * deltaCRLIndicator (2.5.29.27) — маркер delta-CRL. Любое другое
         * critical-расширение дисквалифицирует CRL (RFC 5280 §5.2).
         */
        private val SUPPORTED_CRITICAL_CRL_EXTENSIONS = setOf(Extension.deltaCRLIndicator.id)
    }
}
