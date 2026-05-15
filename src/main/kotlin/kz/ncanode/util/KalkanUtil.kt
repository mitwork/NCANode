@file:JvmName("KalkanUtil")

package kz.ncanode.util

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.tsp.TSPAlgorithms
import org.apache.xml.security.encryption.XMLCipherParameters
import org.apache.xml.security.utils.Constants

/**
 * Вспомогательные методы для работы с KalkanCrypt.
 */

const val GOST3410_256_2015 = "1.2.398.3.10.1.1.2.3.1"
const val GOST3410_512_2015 = "1.2.398.3.10.1.1.2.3.2"

private val HASHING_ALGORITHMS = mapOf(
    TSPAlgorithms.MD5 to "MD5",
    TSPAlgorithms.SHA1 to "SHA1",
    TSPAlgorithms.SHA224 to "SHA224",
    TSPAlgorithms.SHA256 to "SHA256",
    TSPAlgorithms.SHA384 to "SHA384",
    TSPAlgorithms.SHA512 to "SHA512",
    TSPAlgorithms.RIPEMD128 to "RIPEMD128",
    TSPAlgorithms.RIPEMD160 to "RIPEMD160",
    TSPAlgorithms.RIPEMD256 to "RIPEMD256",
    TSPAlgorithms.GOST34311GT to "GOST34311GT",
    TSPAlgorithms.GOST34311 to "GOST34311",
    CMSSignedDataGenerator.DIGEST_GOST3411_2015_256 to "GOST3411-2015-256",
    CMSSignedDataGenerator.DIGEST_GOST3411_2015_512 to "GOST3411-2015-512",
)

/**
 * Метод возвращает алгоритм подписи по OID.
 *
 * @return массив из двух элементов (первый — алгоритм подписи, второй — алгоритм хэширования)
 */
fun getSignMethodByOID(oid: String): Array<String> = when (oid) {
    PKCSObjectIdentifiers.sha1WithRSAEncryption.id -> arrayOf(
        Constants.MoreAlgorithmsSpecNS + "rsa-sha1",
        Constants.MoreAlgorithmsSpecNS + "sha1",
    )
    PKCSObjectIdentifiers.sha256WithRSAEncryption.id -> arrayOf(
        Constants.MoreAlgorithmsSpecNS + "rsa-sha256",
        XMLCipherParameters.SHA256,
    )
    GOST3410_512_2015 -> arrayOf(
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
    )
    GOST3410_256_2015 -> arrayOf(
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256",
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256",
    )
    else -> arrayOf(
        Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311",
        Constants.MoreAlgorithmsSpecNS + "gost34311",
    )
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
fun getTspHashAlgorithmByOid(signOid: String): String = when (signOid) {
    PKCSObjectIdentifiers.sha1WithRSAEncryption.id -> TSPAlgorithms.SHA1
    PKCSObjectIdentifiers.sha256WithRSAEncryption.id -> TSPAlgorithms.SHA256
    GOST3410_256_2015 -> CMSSignedDataGenerator.DIGEST_GOST3411_2015_256
    GOST3410_512_2015 -> CMSSignedDataGenerator.DIGEST_GOST3411_2015_512
    else -> TSPAlgorithms.GOST34311
}

fun getHashingAlgorithmByOID(oid: String): String? = HASHING_ALGORITHMS[oid]
