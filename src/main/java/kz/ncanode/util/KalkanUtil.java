package kz.ncanode.util;

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator;
import kz.gov.pki.kalkan.tsp.TSPAlgorithms;
import lombok.experimental.UtilityClass;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.utils.Constants;

import java.util.HashMap;

/**
 * Вспомогательные методы для работы с KalkanCrypt
 */
@UtilityClass
public class KalkanUtil {
    public final static String GOST3410_256_2015 = "1.2.398.3.10.1.1.2.3.1";
    public final static String GOST3410_512_2015 = "1.2.398.3.10.1.1.2.3.2";

    /**
     * Метод возвращает алгоритм подписи по OID.
     *
     * @param oid OID
     * @return Массив с двумя элементами (Первый = Алгоритм подписи, второй = Алгоритм хэширования)
     */
    public static String[] getSignMethodByOID(String oid) {

        String[] ret = new String[2];

        if (oid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            ret[0] = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
            ret[1] = Constants.MoreAlgorithmsSpecNS + "sha1";
        } else if (oid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            ret[0] = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
            ret[1] = XMLCipherParameters.SHA256;
        } else if (oid.equals(GOST3410_512_2015)) { // GOST3410-2015 512
            ret[0] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
            ret[1] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
        } else if (oid.equals(GOST3410_256_2015)) { // GOST3410-2015 256
            ret[0] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256";
            ret[1] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256";
        } else {
            ret[0] = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
            ret[1] = Constants.MoreAlgorithmsSpecNS + "gost34311";
        }

        return ret;
    }

    /**
     * Возвращает OID хэш-алгоритма, который нужно использовать для TSP-импринта
     * подписи, сделанной ключом с указанным алгоритмом подписи.
     *
     * Для каждого поколения ключей хэш TSP-метки должен соответствовать хэшу
     * самой подписи (мешать GOST 2015-cert + GOST 95-imprint — это
     * mixed-generation, странно и небезопасно). NCALayer (де-факто стандарт
     * клиентских подписей) использует именно эту схему: для GOST 2015-512
     * ключа TSP-импринт идёт по GOST 3411-2015-512 хэшу.
     *
     * @param signOid OID алгоритма подписи (например, cert.getSigAlgOID())
     * @return OID хэш-алгоритма для использования в TSP messageImprint
     */
    public static String getTspHashAlgorithmByOid(String signOid) {
        if (signOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA1;
        }
        if (signOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA256;
        }
        if (signOid.equals(GOST3410_256_2015)) {
            return CMSSignedDataGenerator.DIGEST_GOST3411_2015_256;
        }
        if (signOid.equals(GOST3410_512_2015)) {
            return CMSSignedDataGenerator.DIGEST_GOST3411_2015_512;
        }
        return TSPAlgorithms.GOST34311;
    }

    public static String getHashingAlgorithmByOID(String oid) {
        HashMap<String, String> algos = new HashMap<>();

        algos.put(TSPAlgorithms.MD5,"MD5");
        algos.put(TSPAlgorithms.SHA1,"SHA1");
        algos.put(TSPAlgorithms.SHA224,"SHA224");
        algos.put(TSPAlgorithms.SHA256,"SHA256");
        algos.put(TSPAlgorithms.SHA384,"SHA384");
        algos.put(TSPAlgorithms.SHA512,"SHA512");
        algos.put(TSPAlgorithms.RIPEMD128,"RIPEMD128");
        algos.put(TSPAlgorithms.RIPEMD160,"RIPEMD160");
        algos.put(TSPAlgorithms.RIPEMD256,"RIPEMD256");
        algos.put(TSPAlgorithms.GOST34311GT,"GOST34311GT");
        algos.put(TSPAlgorithms.GOST34311,"GOST34311");
        algos.put(CMSSignedDataGenerator.DIGEST_GOST3411_2015_256,"GOST3411-2015-256");
        algos.put(CMSSignedDataGenerator.DIGEST_GOST3411_2015_512,"GOST3411-2015-512");

        return algos.get(oid);
    }
}
