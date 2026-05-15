package kz.ncanode.service;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.*;
import kz.ncanode.configuration.OcspConfiguration;
import kz.ncanode.dto.ocsp.OcspResult;
import kz.ncanode.dto.ocsp.OcspStatus;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Сервис для работы с сервером OCSP (Проверка сертификатов на отозванность)
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class OcspService {
    /**
     * RFC 8954 рекомендует nonce длиной не менее 16 байт.
     */
    private static final int NONCE_LENGTH = 16;

    /**
     * RFC 6960 §4.2.2.2: для делегированного OCSP-responder'а EKU должен
     * содержать id-kp-OCSPSigning.
     */
    private static final String EKU_OCSP_SIGNING_OID = "1.3.6.1.5.5.7.3.9";

    private final KalkanProvider kalkanProvider;
    private final OcspConfiguration ocspConfiguration;
    private final CloseableHttpClient client;

    /**
     * Выполняет запрос на OCSP серверы и возвращает статус для каждого URL.
     *
     * URL'ы определяются по такому правилу:
     *  1) Если в сертификате есть extension `authorityInfoAccess` с
     *     `id-ad-ocsp` (RFC 5280 §4.2.2.1) — используются URL'ы оттуда.
     *     Cert сам говорит, какой responder обслуживает его revocation.
     *  2) Если AIA отсутствует — fallback на `NCANODE_OCSP_URL` из конфига.
     *
     * URL'ы фильтруются по схеме: разрешаются только http/https
     * (defense-in-depth против SSRF на file:// и т.п.).
     *
     * @param cert   Проверяемый сертификат
     * @param issuer Сертификат удостоверяющего центра, выпустившего {@code cert}
     */
    public List<OcspStatus> verify(CertificateWrapper cert, CertificateWrapper issuer) {
        List<OcspStatus> statuses = new ArrayList<>();

        if (issuer == null) {
            statuses.add(OcspStatus.builder()
                .result(OcspResult.UNKNOWN)
                .message("Cannot find root certificate in NCANode. Try add it using NCANODE_CA_URL variable.")
                .build()
            );

            return statuses;
        }

        for (URL ocspUrl : resolveOcspUrls(cert)) {
            String url = ocspUrl.toString();
            try {
                byte[] nonce = generateOcspNonce();
                OCSPReq request = buildOcspRequest(cert.getX509Certificate().getSerialNumber(), issuer.getX509Certificate(), nonce);

                try (CloseableHttpResponse response = makeRequest(url, request.getEncoded())) {
                    OcspStatus status = processOcspResponse(response.getEntity().getContent(), nonce, issuer);
                    statuses.add(status.toBuilder().url(url).build());
                }
            } catch (IOException | OCSPException | GeneralSecurityException e) {
                statuses.add(OcspStatus.builder()
                    .result(OcspResult.UNKNOWN)
                    .url(url)
                    .message(e.getMessage())
                    .build()
                );
            }
        }

        return statuses;
    }

    /**
     * Определяет, какие OCSP-URL'ы использовать для проверки этого cert'а.
     * Приоритет: AIA-extension cert'а → config fallback.
     */
    private List<URL> resolveOcspUrls(CertificateWrapper cert) {
        List<URL> aiaUrls = cert.getOcspUrls().stream()
            .filter(OcspService::isAllowedScheme)
            .toList();

        if (!aiaUrls.isEmpty()) {
            log.debug("Using OCSP URLs from cert AIA: {}", aiaUrls);
            return aiaUrls;
        }

        List<URL> configUrls = ocspConfiguration.getUrlList().values().stream()
            .filter(OcspService::isAllowedScheme)
            .toList();
        if (!configUrls.isEmpty()) {
            log.debug("Cert has no AIA OCSP URLs, falling back to {} configured URL(s)", configUrls.size());
        }
        return configUrls;
    }

    private static boolean isAllowedScheme(URL url) {
        String scheme = url.getProtocol();
        boolean ok = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        if (!ok) {
            log.warn("Refusing OCSP URL with disallowed scheme: {}", url);
        }
        return ok;
    }

    private OCSPReq buildOcspRequest(BigInteger serialNumber, X509Certificate issuer, byte[] nonce) throws OCSPException {
        final OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
        CertificateID certId = new CertificateID(CertificateID.HASH_SHA256, issuer, serialNumber, kalkanProvider.getName());
        ocspReqGenerator.addRequest(certId);
        Hashtable<Object,Object> ext = new Hashtable<>();
        ext.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, new X509Extension(false, new DEROctetString(new DEROctetString(nonce))) {});
        ocspReqGenerator.setRequestExtensions(new X509Extensions(ext));
        return ocspReqGenerator.generate();
    }

    public byte[] generateOcspNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(nonce);

        return nonce;
    }

    /**
     * Парсит и верифицирует OCSP-ответ. Возвращает финальный статус
     * (ACTIVE / REVOKED / UNKNOWN). Защищает от MITM-атак: подпись ответа
     * сверяется с ключом авторизованного responder'а, nonce обязан совпасть
     * с тем, что мы отправили в запросе.
     */
    private OcspStatus processOcspResponse(InputStream response, byte[] sentNonce, CertificateWrapper issuer)
        throws IOException, OCSPException, NoSuchProviderException, GeneralSecurityException
    {
        OCSPResp resp = new OCSPResp(response);

        if (resp.getStatus() != 0) {
            return OcspStatus.builder()
                .result(OcspResult.UNKNOWN)
                .message("OCSP response status: " + resp.getStatus())
                .build();
        }

        BasicOCSPResp brep = (BasicOCSPResp) resp.getResponseObject();

        // 1) Подпись OCSP-ответа должна быть проверена ключом авторизованного
        // responder'а — либо самого CA (issuer), либо делегированного с EKU
        // id-kp-OCSPSigning, подписанного этим CA. Без этого MITM может вернуть
        // любой статус, и мы бы его приняли как родной.
        X509Certificate responderCert = findVerifiedResponderCertificate(brep, issuer);
        if (responderCert == null) {
            return OcspStatus.builder()
                .result(OcspResult.UNKNOWN)
                .message("OCSP response signature could not be verified against any authorized responder")
                .build();
        }

        // 2) Nonce обязан вернуться и совпасть с отправленным. Если responder
        // его пропустил — это replay-vector: мы могли получить старый ответ.
        byte[] respNonceExt = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
        if (respNonceExt == null) {
            return OcspStatus.builder()
                .result(OcspResult.UNKNOWN)
                .message("OCSP response is missing nonce (replay protection failed)")
                .build();
        }

        try (ASN1InputStream asn1In = new ASN1InputStream(respNonceExt)) {
            DERObject derObj = asn1In.readObject();
            byte[] extV = DEROctetString.getInstance(derObj).getOctets();

            try (ASN1InputStream asn2In = new ASN1InputStream(extV)) {
                derObj = asn2In.readObject();
            }

            if (!Arrays.equals(sentNonce, DEROctetString.getInstance(derObj).getOctets())) {
                return OcspStatus.builder()
                    .result(OcspResult.UNKNOWN)
                    .message("OCSP response nonce does not match request")
                    .build();
            }
        }

        // 3) Freshness: thisUpdate в будущем — аномалия, отклоняем. После
        // nextUpdate — WARN, но используем (аналогично подходу к CRL — отзывы
        // не отменяются, false negative хуже false positive).
        SingleResp[] singleResps = brep.getResponses();
        if (singleResps == null || singleResps.length == 0) {
            return OcspStatus.builder()
                .result(OcspResult.UNKNOWN)
                .message("OCSP response has no single responses")
                .build();
        }
        SingleResp singleResp = singleResps[0];

        Date now = new Date();
        final long clockSkewMs = 5 * 60 * 1000L; // 5 минут на расхождение часов

        if (singleResp.getThisUpdate() != null
            && singleResp.getThisUpdate().getTime() > now.getTime() + clockSkewMs) {
            return OcspStatus.builder()
                .result(OcspResult.UNKNOWN)
                .message("OCSP response thisUpdate is in the future")
                .build();
        }
        if (singleResp.getNextUpdate() != null
            && singleResp.getNextUpdate().getTime() + clockSkewMs < now.getTime()) {
            log.debug("OCSP response is past its nextUpdate={}, still using",
                singleResp.getNextUpdate());
        }

        Object status = singleResp.getCertStatus();

        if (status == null) {
            return OcspStatus.builder()
                .result(OcspResult.ACTIVE)
                .message("OK")
                .build();
        } else if (status instanceof RevokedStatus rev) {
            int reason;

            try {
                reason = rev.getRevocationReason();
            } catch (IllegalStateException e) {
                reason = -1;
            }

            return OcspStatus.builder()
                .result(OcspResult.REVOKED)
                .revocationTime(rev.getRevocationTime())
                .revocationReason(reason)
                .message("OK")
                .build();
        }

        return OcspStatus.builder()
            .result(OcspResult.UNKNOWN)
            .message("Unknown status")
            .build();
    }

    /**
     * Ищет сертификат, чьим ключом подпись на OCSP-ответе сходится, и при этом
     * этот сертификат имеет право быть OCSP-responder'ом для данного CA:
     *  - либо это сам issuer (CA ставит подпись своим же ключом — допустимо);
     *  - либо это делегированный responder, выпущенный этим issuer'ом и
     *    несущий EKU id-kp-OCSPSigning (RFC 6960 §4.2.2.2).
     *
     * Возвращает {@code null}, если ни одна комбинация не сошлась.
     */
    private X509Certificate findVerifiedResponderCertificate(BasicOCSPResp brep, CertificateWrapper issuer)
        throws NoSuchProviderException, OCSPException
    {
        X509Certificate issuerCert = issuer.getX509Certificate();
        String provider = kalkanProvider.getName();

        // Пробуем сначала ключ самого CA — самый частый случай для NCA.
        try {
            if (brep.verify(issuerCert.getPublicKey(), provider)) {
                return issuerCert;
            }
        } catch (OCSPException e) {
            log.debug("OCSP response not signed by CA itself: {}", e.getMessage());
        }

        // Делегированный responder: cert лежит внутри ответа. Проверяем
        // подпись, цепочку до issuer'а и EKU.
        X509Certificate[] embedded = brep.getCerts(provider);
        if (embedded == null) {
            return null;
        }

        for (X509Certificate respCert : embedded) {
            try {
                if (!brep.verify(respCert.getPublicKey(), provider)) {
                    continue;
                }
            } catch (OCSPException e) {
                continue;
            }

            // Цепочка: responder-cert подписан тем же CA.
            if (!respCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                log.debug("Embedded OCSP cert is not issued by our CA");
                continue;
            }
            try {
                respCert.verify(issuerCert.getPublicKey());
            } catch (GeneralSecurityException e) {
                log.debug("Embedded OCSP cert signature does not verify against CA: {}", e.getMessage());
                continue;
            }

            // EKU обязан содержать id-kp-OCSPSigning.
            try {
                List<String> eku = respCert.getExtendedKeyUsage();
                if (eku == null || !eku.contains(EKU_OCSP_SIGNING_OID)) {
                    log.debug("Embedded OCSP cert does not declare id-kp-OCSPSigning EKU");
                    continue;
                }
            } catch (java.security.cert.CertificateParsingException e) {
                continue;
            }

            return respCert;
        }

        return null;
    }

    private CloseableHttpResponse makeRequest(String url, byte[] data) throws IOException {
        final HttpPost httpRequest = new HttpPost(url);
        httpRequest.addHeader("Content-Type", "application/ocsp-request");
        httpRequest.setEntity(new ByteArrayEntity(data));

        return client.execute(httpRequest);
    }
}
