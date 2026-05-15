package kz.ncanode.service;

import kz.ncanode.configuration.CaConfiguration;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.exception.CaException;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Сервис для работы с центром сертификации
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CaService {
    private final static int EXIT_CODE = 32;
    private final static String CA_CACHE_DIR_NAME = "ca";
    private final static String CA_FILE_EXTENSION = ".cer";

    private final ApplicationContext applicationContext;
    private final CaConfiguration caConfiguration;
    private final CloseableHttpClient client;
    private final DirectoryService directoryService;

    @Qualifier("caCrlService")
    private final CrlService caCrlService;

    private final List<CertificateWrapper> certificates = new ArrayList<>();

    @Scheduled(fixedRateString = "${ncanode.ca.ttl}", initialDelay = 0, timeUnit = TimeUnit.MINUTES)
    public void updateCache() {
        if (!caConfiguration.isEnabled()) {
            return;
        }

        updateCache(false);
    }

    public void updateCache(boolean force) {
        synchronized (directoryService) {
            synchronized (certificates) {
                var urls = caConfiguration.getUrlList();

                if (urls.isEmpty()) {
                    log.error("CA certificates urls is empty. Please set NCANODE_CA_URL environment variable.");
                    shutdown();
                }

                log.info("Updating CA certificates cache...");

                final long ttlMillis = (long) caConfiguration.getTtl() * 60_000L;
                final long now = System.currentTimeMillis();

                // Pass 1: загружаем актуальные файлы (скачиваем, если протух TTL
                // или нет на диске) и складываем распарсенные сертификаты
                // в in-memory список. Делаем это до проверок ниже, чтобы цепочка
                // issuer-ов была доступна целиком, независимо от порядка URL.
                final List<CertificateWrapper> loaded = new ArrayList<>(urls.size());
                final List<File> loadedFiles = new ArrayList<>(urls.size());
                final List<URL> loadedUrls = new ArrayList<>(urls.size());

                for (var urlEntry : urls.entrySet()) {
                    File caFile = new File(
                        java.util.Objects.requireNonNull(directoryService.getCachePathFor(CA_CACHE_DIR_NAME)),
                        urlEntry.getKey() + CA_FILE_EXTENSION
                    );
                    boolean stale = caFile.exists() && (now - caFile.lastModified()) > ttlMillis;

                    CertificateWrapper cert;
                    if (force || !caFile.exists() || !caFile.canRead() || stale) {
                        cert = downloadCert(urlEntry.getValue(), caFile);
                    } else {
                        cert = CertificateWrapper.fromFile(caFile);
                    }

                    checkCertForNull(urlEntry, cert, caFile);
                    loaded.add(cert);
                    loadedFiles.add(caFile);
                    loadedUrls.add(urlEntry.getValue());
                }

                // Атомарно подменяем список: с этого момента getRootCertificates()
                // и getRootCertificateFor() видят актуальный набор.
                certificates.clear();
                certificates.addAll(loaded);

                // Pass 2: для каждого сертификата выставляем issuer (теперь
                // доступен по всему списку) и проверяем срок + CA-CRL.
                // Отозванный → WARN, перекачиваем (может быть свежая замена).
                // Протухший по notAfter → INFO, перекачиваем (NCA мог обновить
                // cert по тому же URL). Если на сервере лежит тот же
                // протухший legacy-корень — следующий проход просто примет
                // его как есть; повторная перекачка раз в TTL допустима.
                for (int i = 0; i < loaded.size(); i++) {
                    CertificateWrapper cert = loaded.get(i);
                    cert.setIssuerCertificate(getRootCertificateFor(cert).orElse(null));

                    final boolean dateInvalid = !cert.isDateValid();
                    final boolean revoked = caCrlService.verify(cert).getResult() == CrlResult.REVOKED;

                    if (revoked) {
                        log.warn("CA certificate from {} is revoked, re-downloading", loadedUrls.get(i));
                    } else if (dateInvalid) {
                        log.info("CA certificate from {} is expired (notAfter={}), trying to refresh from server",
                            loadedUrls.get(i), cert.getX509Certificate().getNotAfter());
                    }

                    if (dateInvalid || revoked) {
                        CertificateWrapper refreshed = downloadCert(loadedUrls.get(i), loadedFiles.get(i));
                        if (refreshed != null) {
                            certificates.set(i, refreshed);
                        }
                    }
                }

                // Чистим orphan-файлы: записи прошлых конфигов, не привязанные
                // ни к одному из текущих URL.
                deleteOrphanCacheFiles(urls.keySet());

                log.info("CA certificates cache updated: {} entries", certificates.size());
            }
        }
    }

    private void deleteOrphanCacheFiles(Set<String> validKeys) {
        File cacheDir = directoryService.getCachePathFor(CA_CACHE_DIR_NAME);
        if (cacheDir == null) {
            return;
        }
        File[] files = cacheDir.listFiles();
        if (files == null) {
            return;
        }
        for (File f : files) {
            if (!f.isFile() || !f.getName().endsWith(CA_FILE_EXTENSION)) {
                continue;
            }
            String stem = f.getName().substring(0, f.getName().length() - CA_FILE_EXTENSION.length());
            if (!validKeys.contains(stem)) {
                if (f.delete()) {
                    log.info("Deleted orphan CA cache file: {}", f.getName());
                } else {
                    log.warn("Could not delete orphan CA cache file: {}", f);
                }
            }
        }
    }

    public CertificateWrapper downloadCert(URL url, File file) {
        try {
            log.info("Downloading CA file: {}", url.toString());
            download(url, file);
            log.info("Download complete");
            return CertificateWrapper.fromFile(file);
        } catch (CaException e) {
            log.error(e.getMessage());
            return null;
        }
    }

    /**
     * Возвращает доверенный корневой сертификат для сертификата ЭЦП
     *
     * @param cert Сертификат из ЭЦП
     * @return Сертификат Удостоверяющего центра, либо ничего
     */
    public Optional<CertificateWrapper> getRootCertificateFor(CertificateWrapper cert) {
        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            return Optional.empty();
        }

        return getRootCertificates().stream()
            .filter(root -> cert.getIssuerX500Principal().equals(root.getSubjectX500Principal()) && cert.verify(root.getPublicKey()))
            .findFirst();
    }

    public List<CertificateWrapper> getRootCertificates() {
        synchronized (directoryService) {
            synchronized (certificates) {
                List<CertificateWrapper> certs;

                if (!certificates.isEmpty()) {
                    certs = certificates;
                } else {
                    certs = Arrays.stream(Objects.requireNonNull(directoryService.getCachePathFor(CA_CACHE_DIR_NAME).listFiles()))
                        .filter(f -> f.isFile() && f.canRead() && f.getName().endsWith(CA_FILE_EXTENSION))
                        .map(CertificateWrapper::fromFile)
                        .filter(Objects::nonNull)
                        .toList();

                    certificates.addAll(certs);
                }

                return certs;
            }
        }
    }

    public void download(URL url, File file) {
        try (CloseableHttpResponse response = client.execute(new HttpGet(url.toString()))) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new CaException(String.format("Cannot download file: %s", url));
            }

            HttpEntity entity = response.getEntity();

            if (entity == null) {
                throw new CaException(String.format("Got empty request from: %s", url));
            }

            try(FileOutputStream out = new FileOutputStream(file)) {
                entity.writeTo(out);
            }
        } catch (IOException e) {
            throw new CaException(String.format("Cannot download file: %s", url), e);
        }
    }

    private void shutdown() {
        SpringApplication.exit(applicationContext, () -> EXIT_CODE);
        System.exit(EXIT_CODE);
    }

    private void checkCertForNull(final Map.Entry<String, URL> urlEntry, final CertificateWrapper cert, final File caFile) {
        if (cert == null) {
            log.error("Cannot open CA certificate from: '{}'. File name: {}", urlEntry.getValue().toString(), caFile.getAbsolutePath());
            shutdown();
            return;
        }
    }
}
