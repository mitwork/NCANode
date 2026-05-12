package kz.ncanode.service;

import kz.gov.pki.kalkan.asn1.ASN1Encodable;
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSException;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.*;
import kz.ncanode.configuration.TspConfiguration;
import kz.ncanode.exception.TspException;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class TspService {
    /**
     * OID id-kp-timeStamping (RFC 3161): сертификат TSA должен содержать его в EKU.
     */
    private static final String EKU_TIME_STAMPING_OID = "1.3.6.1.5.5.7.3.8";

    private final CloseableHttpClient client;
    private final TspConfiguration tspConfiguration;
    private final CertificateService certificateService;

    public TimeStampToken create(byte[] data, String hashAlg, String reqPolicy) {
        try {
            // Generate hash
            MessageDigest md = MessageDigest.getInstance(hashAlg, KalkanProvider.PROVIDER_NAME);
            md.update(data);
            byte[] hash = md.digest();

            // Create TSP request
            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.setCertReq(true);
            reqGen.setReqPolicy(reqPolicy);
            TimeStampRequest request = reqGen.generate(hashAlg, hash, generateNonce());
            byte[] reqData = request.getEncoded();

            int retries = 0;
            int maxRetries = Math.max(1, tspConfiguration.getRetries());
            RuntimeException lastException = null;

            while (retries < maxRetries) {
                try {
                    TimeStampResponse response = makeRequest(reqData);
                    response.validate(request);

                    return response.getTimeStampToken();
                } catch (RuntimeException e) {
                    lastException = e;
                    retries++;
                }
            }

            throw lastException;
        } catch (GeneralSecurityException|IOException|TSPException e) {
            log.error("TSP creation failure.", e);
            throw new TspException("TSP creation failure", e);
        }
    }

    /**
     * Полная криптографическая проверка TSP-токена в режиме CAdES-T:
     *  1) подпись TSA на токене валидна;
     *  2) messageImprint токена совпадает с хэшем подписи внешнего подписанта
     *     (т.е. метка действительно проставлена для этой подписи, а не подложена);
     *  3) сертификат TSA содержит EKU id-kp-timeStamping (RFC 3161);
     *  4) сертификат TSA и его эмитент валидны на момент genTime метки
     *     (а не на текущую дату — иначе протухший TSA сломал бы все архивные подписи).
     *
     * Возвращает {@link TimeStampTokenInfo}, только если ВСЕ проверки прошли —
     * иначе пустой Optional (с предупреждением в логе). Никаких исключений
     * наружу не пробрасывает: некорректный TSP не должен валить верификацию
     * внешней подписи, он лишь не даёт права использовать genTime как
     * "момент истины".
     */
    public Optional<TimeStampTokenInfo> verify(
        CMSSignedData tspCms,
        byte[] outerSignerSignature,
        boolean checkOcsp,
        boolean checkCrl
    ) {
        try {
            Collection<?> tspSignersCol = tspCms.getSignerInfos().getSigners();
            if (tspSignersCol.isEmpty()) {
                log.warn("TSP token has no signers");
                return Optional.empty();
            }
            SignerInformation tspSigner = (SignerInformation) tspSignersCol.iterator().next();

            CertStore tsaCertStore = tspCms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
            Collection<?> tsaCerts = tsaCertStore.getCertificates(tspSigner.getSID());
            if (tsaCerts.isEmpty()) {
                log.warn("TSP token does not embed TSA certificate");
                return Optional.empty();
            }
            CertificateWrapper tsaCert = new CertificateWrapper((X509Certificate) tsaCerts.iterator().next());

            // 1) Подпись TSA на токене. Используем ручную верификацию вместо
            // TimeStampToken.validate(...) — последний жёстко проверяет срок
            // действия TSA на текущий момент, что ломает архивные метки.
            if (!tspSigner.verify(tsaCert.getPublicKey(), KalkanProvider.PROVIDER_NAME)) {
                log.warn("TSP token signature verification failed");
                return Optional.empty();
            }

            TimeStampTokenInfo tspi = new TimeStampToken(tspCms).getTimeStampInfo();

            // 2) Имрпринт должен быть хэшем именно подписи внешнего подписанта.
            String imprintAlgName = KalkanUtil.getHashingAlgorithmByOID(tspi.getMessageImprintAlgOID());
            if (imprintAlgName == null) {
                log.warn("Unsupported TSP imprint algorithm OID: {}", tspi.getMessageImprintAlgOID());
                return Optional.empty();
            }
            MessageDigest md = MessageDigest.getInstance(imprintAlgName, KalkanProvider.PROVIDER_NAME);
            byte[] expectedImprint = md.digest(outerSignerSignature);
            if (!Arrays.equals(expectedImprint, tspi.getMessageImprintDigest())) {
                log.warn("TSP messageImprint does not match outer signer signature");
                return Optional.empty();
            }

            // 3) EKU id-kp-timeStamping — обязателен для TSA по RFC 3161.
            List<String> eku = tsaCert.getExtendedKeyUsage();
            if (eku == null || !eku.contains(EKU_TIME_STAMPING_OID)) {
                log.warn("TSA certificate does not declare id-kp-timeStamping EKU");
                return Optional.empty();
            }

            // 4) TSA-цепочка валидна на genTime.
            Date genTime = tspi.getGenTime();
            if (genTime == null) {
                log.warn("TSP token has no genTime");
                return Optional.empty();
            }

            certificateService.attachValidationData(tsaCert, checkOcsp, checkCrl);
            if (!tsaCert.isValid(genTime, checkOcsp, checkCrl)) {
                log.warn("TSA certificate is not valid at TSP genTime {}", genTime);
                return Optional.empty();
            }

            return Optional.of(tspi);
        } catch (Exception e) {
            log.warn("TSP verification error: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    public Optional<TimeStampTokenInfo> info(CMSSignedData data) {
        try {
            TimeStampToken tspt = new TimeStampToken(data);
            X509CertSelector signerConstraints = tspt.getSID();
            CertStore certs = data.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
            Collection<?> certCollection = certs.getCertificates(signerConstraints);
            Iterator<?> certIt = certCollection.iterator();

            if (!certIt.hasNext()) {
                return Optional.empty();
            }

            X509Certificate cert = (X509Certificate) certIt.next();
            tspt.validate(cert, KalkanProvider.PROVIDER_NAME);

            return Optional.of(tspt.getTimeStampInfo());
        } catch (TSPException | IOException | NoSuchProviderException | NoSuchAlgorithmException | CMSException | CertificateExpiredException | CertStoreException | CertificateNotYetValidException e) {
            log.error("TSP verification error.", e);
            return Optional.empty();
        }
    }

    public BigInteger generateNonce() {
        return BigInteger.valueOf(System.currentTimeMillis());
    }

    public SignerInformation addTspToSigner(SignerInformation signer, X509Certificate cert, String useTsaPolicy) throws NoSuchAlgorithmException, NoSuchProviderException, TSPException, IOException {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        ASN1EncodableVector vector = new ASN1EncodableVector();

        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        TimeStampToken tsp = create(signer.getSignature(), KalkanUtil.getTspHashAlgorithmByOid(cert.getSigAlgOID()), useTsaPolicy);
        byte[] ts = tsp.getEncoded();
        ASN1Encodable signatureTimeStamp = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(Util.byteToASN1(ts)));
        vector.add(signatureTimeStamp);

        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(vector));
    }

    private TimeStampResponse makeRequest(byte[] request) {
        URL url = tspConfiguration.getParsedUrl().orElseThrow(() -> {
            log.error("Invalid TSP url");
            return new TspException("Invalid tsp url");
        });

        HttpPost httpPost = new HttpPost(url.toString());
        httpPost.setHeader("Content-Type", "application/timestamp-query");
        httpPost.setEntity(new ByteArrayEntity(request));

        try (CloseableHttpResponse response = client.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();

            if (statusCode != HttpStatus.SC_OK) {
                log.error("Invalid TSP response status: {}", statusCode);
                throw new TspException(String.format("Invalid TSP response status: %d", statusCode));
            }

            return new TimeStampResponse(response.getEntity().getContent());
        } catch (IOException | TSPException e) {
            throw new TspException("TSP request failure.", e);
        }
    }
}
