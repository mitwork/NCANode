@file:JvmName("Util")

package kz.ncanode.util

import kz.gov.pki.kalkan.asn1.ASN1InputStream
import kz.gov.pki.kalkan.asn1.DERObject
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.MalformedURLException
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.regex.Pattern

private val log: Logger = LoggerFactory.getLogger("kz.ncanode.util.Util")
private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

fun sha1(data: String): String = try {
    val crypt = MessageDigest.getInstance("SHA-1")
    crypt.reset()
    crypt.update(data.toByteArray(StandardCharsets.UTF_8))
    bytesToHex(crypt.digest())
} catch (e: NoSuchAlgorithmException) {
    // SHA-1 в JDK всегда доступен; этот блок реально не должен срабатывать.
    log.error("SHA-1 algorithm is not available in JDK", e)
    ""
}

fun bytesToHex(bytes: ByteArray): String {
    val hexChars = CharArray(bytes.size * 2)
    for (j in bytes.indices) {
        val v = bytes[j].toInt() and 0xFF
        hexChars[j * 2] = HEX_CHARS[v ushr 4]
        hexChars[j * 2 + 1] = HEX_CHARS[v and 0x0F]
    }
    return String(hexChars)
}

fun createNewUrl(url: String?, log: Logger): URL? {
    if (url == null) return null
    val trimmed = url.trim()
    // Java URL-конструктор lenient: пропускает строки с whitespace/control
    // символами, оставляя их в path. Но URI.create() (используется в HttpGet)
    // strict — падает на таких символах. Чтобы не получить отложенный
    // URISyntaxException на этапе скачивания, фильтруем здесь.
    //
    // Реальный кейс: легаси-NCA CA-cert'ы содержат CRL DP с двумя URL'ами,
    // склеенными через "\n URL=...". Это malformed cert, но он существует
    // и не повлияет на остальные DistributionPoints, если мы просто
    // отбросим такие записи.
    if (trimmed.any { it.isWhitespace() || Character.isISOControl(it) }) {
        // DEBUG, не WARN: типичный кейс — легаси NCA-cert'ы
        // (nca_gost.crt / nca_rsa.crt) с CRL DP вида
        // "url1\n               URL=url2" (псевдо-human-readable
        // форматирование, попавшее в ASN.1 IA5String). NCA выдала
        // эти CA из активного обслуживания, починить с нашей стороны
        // нельзя. Шум в WARN бесполезен; при diagnose видно через --debug.
        log.debug("Skipping malformed URL with whitespace/control characters: '{}'", trimmed)
        return null
    }
    return try {
        URL(trimmed)
    } catch (e: MalformedURLException) {
        log.warn("Cannot parse url '{}'", trimmed, e)
        null
    }
}

fun urlMap(url: String?, log: Logger): Map<String, URL> {
    if (url.isNullOrBlank()) return emptyMap()
    return url.split(Regex("\\s+"))
        .asSequence()
        .mapNotNull { createNewUrl(it, log) }
        .associateBy { sha1(it.toString()) }
}

fun byteToASN1(data: ByteArray): DERObject =
    ASN1InputStream(data.inputStream()).use { it.readObject() }

fun getDigestAlgorithmOidBYSignAlgorithmOid(signOid: String): String = when (signOid) {
    PKCSObjectIdentifiers.sha1WithRSAEncryption.id -> CMSSignedDataGenerator.DIGEST_SHA1
    PKCSObjectIdentifiers.sha256WithRSAEncryption.id -> CMSSignedDataGenerator.DIGEST_SHA256
    "1.2.398.3.10.1.1.2.3.1" -> CMSSignedDataGenerator.DIGEST_GOST3411_2015_256
    "1.2.398.3.10.1.1.2.3.2" -> CMSSignedDataGenerator.DIGEST_GOST3411_2015_512
    else -> CMSSignedDataGenerator.DIGEST_GOST34311_95
}

fun findAllUrls(str: String): List<String> {
    val p = Pattern.compile("https?://[^\\s]+", Pattern.CASE_INSENSITIVE)
    val matcher = p.matcher(str)
    val urls = mutableListOf<String>()
    while (matcher.find()) {
        urls.add(str.substring(matcher.start(), matcher.end()))
    }
    return urls
}
