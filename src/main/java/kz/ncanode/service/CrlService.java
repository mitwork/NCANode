package kz.ncanode.service;

import kz.ncanode.configuration.crl.CrlConfiguration;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.dto.crl.CrlStatus;
import kz.ncanode.exception.CrlException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.support.PeriodicTrigger;

import jakarta.annotation.PostConstruct;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Сервис для реализоции механизма проверки сертификатов в CRL
 */
@Slf4j
@RequiredArgsConstructor
public class CrlService {
    public final static String CRL_DEFAULT = "default";
    public final static String CRL_CA      = "ca-crl";
    private final static String CRL_FILE_EXTENSION = ".crl";

    private final DirectoryService directoryService;
    private final CrlConfiguration crlConfiguration;
    private final CloseableHttpClient client;
    private final TaskScheduler taskScheduler;
    private final String crlServiceType;

    /**
     * Каждый CRL-сервис (default vs ca-crl) живёт в собственной поддиректории
     * кэша. Без namespacing'а оба инстанса делят `crl/full` и `crl/delta`,
     * и orphan-cleanup одного удаляет файлы другого как чужие.
     */
    private String cacheFullDir() {
        return "crl/" + crlServiceType + "/full";
    }

    private String cacheDeltaDir() {
        return "crl/" + crlServiceType + "/delta";
    }

    /**
     * Кэш для CRL'ей, скачанных по cRLDistributionPoints из самого cert'а
     * (lazy fetch при первой верификации cert'а от неизвестного CA).
     */
    private String cacheOnDemandDir() {
        return "crl/" + crlServiceType + "/ondemand";
    }

    /**
     * In-memory кэш распарсенных и подпись-верифицированных CRL'ей.
     * Включается через {@code NCANODE_CRL_CACHE_ENABLED} (по умолчанию true).
     *
     * Без кэша на каждый verify-call делается полный {@code loadCrl} +
     * {@code crl.verify(issuerKey)} для каждого файла в каталоге. Для крупных
     * GOST 2015 CRL'ей (десятки MB) это уходит на десятки секунд.
     * С кэшем — миллисекунды (только {@code isRevoked} lookup).
     *
     * Инвалидация: автоматически по {@code lastModified} файла.
     * Repeat-verify против того же ключа issuer'а не делается повторно
     * (cmp encoded key bytes).
     */
    private record CachedCrl(X509CRL crl, long fileMtime, byte[] verifiedAgainstKeyEncoded) {}
    private final java.util.concurrent.ConcurrentHashMap<String, CachedCrl> crlMemCache =
        new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Возвращает распарсенный CRL, используя in-memory кэш если включён.
     * При промахе или изменении файла — re-parse, кэшируем без verified-key
     * (signature проверится отдельно).
     */
    private X509CRL loadCachedCrl(File file) {
        if (!crlConfiguration.isCacheEnabled()) {
            return loadCrl(file);
        }
        String key = file.getAbsolutePath();
        if (key == null) {
            // Без стабильного идентификатора кэшировать нельзя — парсим напрямую.
            // Срабатывает в основном на моках Mockito, где getAbsolutePath() = null.
            return loadCrl(file);
        }
        long mtime = file.lastModified();
        CachedCrl cached = crlMemCache.get(key);
        if (cached != null && cached.fileMtime == mtime) {
            return cached.crl;
        }
        X509CRL parsed = loadCrl(file);
        crlMemCache.put(key, new CachedCrl(parsed, mtime, null));
        return parsed;
    }

    /**
     * Криптопроверка подписи CRL ключом issuer'а с кэшированием.
     * Если подпись уже была успешно проверена против того же ключа и
     * файл не менялся — повторно не верифицируется. Throws — как у
     * {@code X509CRL.verify}, если cert'у нельзя доверять.
     */
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
     *
     * @param caCerts набор доверенных CA для матчинга по
     *                {@code X500Principal} CRL-issuer'а; если issuer не
     *                нашёлся — парсим CRL без signature-верификации
     *                (она сделается лениво при verify cert'а если потребуется)
     */
    public void warmCache(List<CertificateWrapper> caCerts) {
        if (!crlConfiguration.isCacheEnabled()) {
            log.debug("CRL cache disabled for '{}', skipping warmup", crlServiceType);
            return;
        }

        int parsed = 0;
        int sigVerified = 0;
        int errors = 0;

        for (String dir : List.of(cacheFullDir(), cacheDeltaDir(), cacheOnDemandDir())) {
            for (File crlFile : getCrlFiles(dir)) {
                try {
                    X509CRL crl = loadCachedCrl(crlFile);
                    parsed++;

                    final X500Principal crlIssuer = crl.getIssuerX500Principal();
                    PublicKey issuerKey = caCerts.stream()
                        .filter(ca -> ca.getSubjectX500Principal().equals(crlIssuer))
                        .map(CertificateWrapper::getPublicKey)
                        .findFirst()
                        .orElse(null);

                    if (issuerKey != null) {
                        try {
                            verifyCachedSignature(crlFile, crl, issuerKey);
                            sigVerified++;
                        } catch (GeneralSecurityException e) {
                            log.debug("CRL {} signature verify failed during warmup: {}",
                                crlFile.getName(), e.getMessage());
                        }
                    }
                } catch (Exception e) {
                    errors++;
                    log.warn("Failed to warm CRL {}: {}", crlFile.getName(), e.getMessage());
                }
            }
        }

        log.info("CRL cache warmup for '{}': {} parsed, {} signature-verified, {} errors",
            crlServiceType, parsed, sigVerified, errors);
    }

    private void verifyCachedSignature(File file, X509CRL crl, PublicKey issuerKey) throws GeneralSecurityException {
        if (!crlConfiguration.isCacheEnabled()) {
            crl.verify(issuerKey);
            return;
        }
        String key = file.getAbsolutePath();
        if (key == null) {
            crl.verify(issuerKey);
            return;
        }
        long mtime = file.lastModified();
        byte[] keyEnc = issuerKey.getEncoded();
        CachedCrl cached = crlMemCache.get(key);
        if (cached != null
            && cached.fileMtime == mtime
            && cached.verifiedAgainstKeyEncoded != null
            && Arrays.equals(cached.verifiedAgainstKeyEncoded, keyEnc)) {
            return;
        }
        crl.verify(issuerKey);
        crlMemCache.put(key, new CachedCrl(crl, mtime, keyEnc));
    }

    @PostConstruct
    private void initializeScheduler() {
        if (crlConfiguration.getTtl() == null || crlConfiguration.getTtl() < 1) {
            return;
        }

        log.info("Initializing '{}' CRL Service...", crlServiceType);
        val periodicTrigger = new PeriodicTrigger(crlConfiguration.getTtl(), TimeUnit.MINUTES);
        periodicTrigger.setInitialDelay(0);
        periodicTrigger.setFixedRate(true);
        taskScheduler.schedule(() -> updateCache(false, crlConfiguration, cacheFullDir()), periodicTrigger);
    }

    @PostConstruct
    private void initializeDeltaScheduler() {
        if (crlConfiguration.getDelta().getTtl() == null || crlConfiguration.getDelta().getTtl() < 1) {
            return;
        }

        log.info("Initializing '{}' CRL Delta Service...", crlServiceType);
        val periodicTrigger = new PeriodicTrigger(crlConfiguration.getDelta().getTtl(), TimeUnit.MINUTES);
        periodicTrigger.setInitialDelay(0);
        periodicTrigger.setFixedRate(true);
        taskScheduler.schedule(() -> updateCache(false, crlConfiguration.getDelta(), cacheDeltaDir()), periodicTrigger);
    }

    /**
     * Проверка сертификата в CRL.
     *
     * Применяются только CRL'и, выпущенные тем же CA, что и проверяемый
     * сертификат, не истёкшие по {@code nextUpdate} и с валидной подписью
     * издателя (если у нас есть его публичный ключ). Без этих фильтров серийник
     * сертификата мог бы случайно совпасть с серийником из CRL другого CA, или
     * злонамеренно подложенный CRL ложно отозвал бы валидный сертификат.
     *
     * @param cert Сертификат с заполненным {@code issuerCertificate} (через
     *             {@code CertificateService.attachValidationData}). Если issuer
     *             не задан, проверка подписи CRL пропускается с WARN'ом —
     *             совпадение серийников всё равно покажет отзыв, но без
     *             криптографической гарантии аутентичности CRL.
     */
    public CrlStatus verify(CertificateWrapper cert) {
        if (!crlConfiguration.isEnabled()) {
            return CrlStatus.builder()
                .result(CrlResult.ACTIVE)
                .build();
        }

        final X500Principal certIssuer = cert.getIssuerX500Principal();
        final Date now = new Date();
        // Для self-signed корневых CA issuer и subject совпадают, и подпись
        // на CRL стоит ключом этого же корня — используем его собственный
        // публичный ключ, а не ждём отдельного "issuerCertificate" в trust store.
        final boolean selfSigned = certIssuer.equals(cert.getSubjectX500Principal());
        final PublicKey issuerKey = Optional.ofNullable(cert.getIssuerCertificate())
            .map(CertificateWrapper::getPublicKey)
            .orElseGet(() -> selfSigned ? cert.getPublicKey() : null);

        // On-demand fetch: cert указывает в своём cRLDistributionPoints, откуда
        // качать CRL. Это primary-источник по RFC 5280 §4.2.1.13. Если URL'ы
        // ещё не закэшированы или протухли по TTL — синхронно докачиваем,
        // тогда основной цикл ниже их подхватит. Конфиг-CRL'и продолжают
        // обслуживаться schedule'ом и тоже остаются в cache (см. updateCache).
        fetchOnDemandCrls(cert);

        for (final String cacheDirectory : List.of(cacheDeltaDir(), cacheFullDir(), cacheOnDemandDir())) {
            for (File crlFile : getCrlFiles(cacheDirectory)) {
                final X509CRL crl;
                try {
                    crl = loadCachedCrl(crlFile);
                } catch (ServerException e) {
                    log.warn("Skipping unreadable CRL file: {}", crlFile.getName());
                    continue;
                }

                // CRL должен быть выпущен тем же CA, что и проверяемый сертификат.
                if (!crl.getIssuerX500Principal().equals(certIssuer)) {
                    continue;
                }

                // RFC 5280 §5.1.2.5: после nextUpdate CRL формально считается
                // устаревшим. Мы не блокируем его использование (для отозванных
                // сертификатов хуже false negative, чем false positive — отзывы
                // не отменяются). DEBUG, а не WARN: либо CA сам перестал
                // публиковать новые CRL (легаси-инфраструктура), либо у нас
                // отстаёт TTL — оба случая операционно нормальные, не повод
                // спамить WARN'ом в каждый цикл обновления.
                if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now)) {
                    log.debug("CRL {} is past its nextUpdate={}, still using for revocation check",
                        crlFile.getName(), crl.getNextUpdate());
                }

                // Подпись CRL должна быть подтверждена ключом издателя.
                if (issuerKey != null) {
                    try {
                        verifyCachedSignature(crlFile, crl, issuerKey);
                    } catch (GeneralSecurityException e) {
                        // Это уже реальная проблема — подпись CRL не сходится,
                        // либо ключ от другого CA. Такой CRL пропускаем.
                        log.warn("CRL {} signature does not verify against issuer key: {}",
                            crlFile.getName(), e.getMessage());
                        continue;
                    }
                } else {
                    // Issuer'а нет в trust store (типично для легаси-CA,
                    // чьи корни выведены из активного обслуживания и в
                    // NCANODE_CA_URL не лежат). Криптопроверку CRL пропускаем,
                    // но сам CRL используем для проверки серийных номеров.
                    // DEBUG, потому что состояние стабильное и регулярного
                    // внимания оператора не требует.
                    log.debug("Issuer certificate not available for {}, using CRL {} without signature verification",
                        cert.getSubjectX500Principal(), crlFile.getName());
                }

                if (crl.isRevoked(cert.getX509Certificate())) {
                    return Optional.ofNullable(crl.getRevokedCertificate(cert.getX509Certificate()))
                        .map( entry -> CrlStatus.builder()
                            .result(CrlResult.REVOKED)
                            .file(crlFile.getName())
                            .revocationDate(entry.getRevocationDate())
                            .reason(Optional.ofNullable(entry.getRevocationReason()).map(CRLReason::toString).orElse(""))
                            .build()
                        ).orElse(CrlStatus.builder()
                            .result(CrlResult.REVOKED)
                            .build()
                        );
                }
            }
        }

        return CrlStatus.builder()
            .result(CrlResult.ACTIVE)
            .build();
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
     * Примечание про delta-CRL: здесь delta обрабатывается как ещё один
     * отдельный CRL-эндпоинт с более частым обновлением, а не как RFC 5280
     * §5.2.4 delta CRL поверх base (с CRLNumber / BaseCRLNumber). Это работает
     * для NCA, который по delta-URL отдаёт полноценный CRL; для строго
     * совместимой реализации потребовалось бы объединять записи delta + base
     * по их номерам.
     *
     * @param force Если true, то кэш будет обновлен в любом случае
     */
    public synchronized void updateCache(boolean force, CrlConfiguration crlConfiguration, String cacheDirectory) {
        synchronized (directoryService) {
            if (!crlConfiguration.isEnabled() || crlConfiguration.getTtl() <= 0) {
                return;
            }

            log.info("Updating CRL cache for '{}'...", cacheDirectory);
            final long currentTime = System.currentTimeMillis();
            final long ttlMillis = (long) crlConfiguration.getTtl() * 60_000L;

            int updatedCount = 0;

            for (var crlEntry : crlConfiguration.getUrlList().entrySet()) {
                File crlFile = new File(
                    directoryService.getCachePathFor(cacheDirectory).orElseThrow(),
                    crlEntry.getKey() + CRL_FILE_EXTENSION
                );

                boolean stale = !crlFile.exists()
                    || !crlFile.isFile()
                    || !crlFile.canRead()
                    || (currentTime - crlFile.lastModified()) > ttlMillis;

                if (!force && !stale) {
                    log.debug("CRL file {} is fresh, keeping", crlFile.getName());
                    continue;
                }

                downloadCrl(cacheDirectory, crlEntry.getValue());
                updatedCount++;
            }

            // Удаляем orphan-файлы: записи прошлых конфигов, которых больше нет
            // в списке URL'ов.
            deleteOrphanCrlFiles(crlConfiguration.getUrlList().keySet(), cacheDirectory);

            if (updatedCount == 0) {
                log.info("Nothing to update in CRL cache for '{}'", cacheDirectory);
            } else {
                log.info("{} files updated in CRL cache for '{}'", updatedCount, cacheDirectory);
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
    private void fetchOnDemandCrls(CertificateWrapper cert) {
        List<URL> crlUrls = cert.getCrlList();
        if (crlUrls.isEmpty()) {
            return;
        }

        final long ttlMillis = (long) crlConfiguration.getTtl() * 60_000L;
        final long now = System.currentTimeMillis();
        final String dirName = cacheOnDemandDir();
        File cacheDir = directoryService.getCachePathFor(dirName).orElse(null);
        if (cacheDir == null) {
            return;
        }

        for (URL url : crlUrls) {
            if (!isAllowedCrlScheme(url)) {
                continue;
            }
            String fileName = Util.sha1(url.toString()) + CRL_FILE_EXTENSION;

            // Дедуп: если URL уже покрывается scheduled-flow'ом (т.е. файл
            // уже есть в config-кэше full или delta), не качаем дубликат
            // в ondemand. Reuse того же файла, что обновляет scheduled-job
            // — экономит диск и убирает удвоенную работу при verify.
            if (isAlreadyInConfigCache(fileName)) {
                log.debug("CRL URL already covered by config cache, skipping on-demand: {}", url);
                continue;
            }

            File crlFile = new File(cacheDir, fileName);

            boolean stale = !crlFile.exists()
                || !crlFile.isFile()
                || !crlFile.canRead()
                || (now - crlFile.lastModified()) > ttlMillis;

            if (!stale) {
                continue;
            }

            log.debug("On-demand fetching CRL from cert CRL-DP: {}", url);
            downloadCrl(dirName, url);
        }
    }

    /**
     * Проверяет, лежит ли файл с таким именем в `full` или `delta` каталогах
     * (то есть обслуживается scheduled-update'ом из {@code NCANODE_CRL_URL} /
     * {@code NCANODE_CA_CRL_URL}). Если да — on-demand fetch для этого URL
     * не нужен, иначе получим два одинаковых файла в двух каталогах и
     * двойную работу при verify.
     */
    private boolean isAlreadyInConfigCache(String fileName) {
        return fileExistsIn(cacheFullDir(), fileName)
            || fileExistsIn(cacheDeltaDir(), fileName);
    }

    private boolean fileExistsIn(String dirName, String fileName) {
        File dir = directoryService.getCachePathFor(dirName).orElse(null);
        if (dir == null) {
            return false;
        }
        return new File(dir, fileName).isFile();
    }

    private static boolean isAllowedCrlScheme(URL url) {
        String scheme = url.getProtocol();
        boolean ok = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        if (!ok) {
            log.warn("Refusing CRL URL with disallowed scheme: {}", url);
        }
        return ok;
    }

    private void deleteOrphanCrlFiles(Set<String> validKeys, String cacheDirName) {
        File cacheDir = directoryService.getCachePathFor(cacheDirName).orElse(null);
        if (cacheDir == null) {
            return;
        }
        File[] files = cacheDir.listFiles();
        if (files == null) {
            return;
        }
        for (File f : files) {
            if (!f.isFile() || !f.getName().endsWith(CRL_FILE_EXTENSION)) {
                continue;
            }
            String stem = f.getName().substring(0, f.getName().length() - CRL_FILE_EXTENSION.length());
            if (!validKeys.contains(stem)) {
                if (f.delete()) {
                    log.info("Deleted orphan CRL cache file: {}", f.getName());
                } else {
                    log.warn("Could not delete orphan CRL cache file: {}", f);
                }
            }
        }
    }


    /**
     * Загружает CRL файл
     *
     * @param file
     * @return
     */
    public X509CRL loadCrl(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
        } catch (IOException | CRLException | CertificateException e) {
            log.error("Cannot load CRL file \"{}\"", file, e);
            throw new ServerException(String.format("Cannot load CRL file \"%s\"", file.getName()), e);
        }
    }

    /**
     * Скачивает CRL файл в директорию
     *
     * @param cacheDirName
     * @param url
     */
    public void downloadCrl(String cacheDirName, URL url) {
        try {
            String crlUrl = url.toString();
            String crlFileName = Util.sha1(crlUrl) + CRL_FILE_EXTENSION;

            log.info("Downloading CRL file from: {}", crlUrl);
            final File downloadedFile = download(crlUrl, getCrlCacheFilePathFor(cacheDirName, crlFileName).toPath());
            log.info("CRL file \"{}\" successfully downloaded. Size: {} bytes", crlFileName, downloadedFile.length());
        } catch (CrlException e) {
            log.error("CRL File download failure", e.getCause());
        }
    }

    /**
     * Возвращает список CRL файлов в указанной директории
     *
     * @param cacheDirName
     * @return
     */
    public List<File> getCrlFiles(String cacheDirName) {
        return Arrays.stream(Objects.requireNonNull(directoryService.getCachePathFor(cacheDirName).orElseThrow().listFiles()))
            .filter(file -> file.isFile() && file.canRead() && file.getName().endsWith(CRL_FILE_EXTENSION))
            .toList();
    }

    private File download(String url, Path path) throws CrlException {
        // Качаем во временный файл и атомарно подменяем. Если запрос упал
        // или провайдер вернул ошибку — старый CRL на диске остаётся целым,
        // и проверки revocation продолжают работать на нём до следующего цикла.
        final Path tmpPath = path.resolveSibling(path.getFileName().toString() + ".tmp");
        try(CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int status = response.getStatusLine().getStatusCode();

            if (status != HttpStatus.OK.value()) {
                throw new CrlException(String.format("Cannot download file from: %s. Got HTTP status: %d", url, status));
            }

            HttpEntity entity = response.getEntity();

            if (entity == null) {
                throw new CrlException(String.format("Got empty request from: %s", url));
            }

            try(FileOutputStream out = new FileOutputStream(tmpPath.toFile())) {
                entity.writeTo(out);
            }

            try {
                Files.move(tmpPath, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException amns) {
                Files.move(tmpPath, path, StandardCopyOption.REPLACE_EXISTING);
            }

            return path.toFile();
        } catch (IOException e) {
            throw new CrlException(e.getMessage(), e);
        } finally {
            // На случай если rename не успел выполниться — чистим хвост.
            try {
                Files.deleteIfExists(tmpPath);
            } catch (IOException ignored) {
                // best-effort: оставить файл лучше, чем падать в finally
            }
        }
    }

    private File getCrlCacheFilePathFor(String cacheDirName, String fileName) {
        return new File(directoryService.getCachePathFor(cacheDirName).orElseThrow(), fileName);
    }
}
