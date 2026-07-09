@file:JvmName("Util")

package kz.ncanode.util

import kz.gov.pki.kalkan.asn1.ASN1InputStream
import kz.gov.pki.kalkan.asn1.DERObject
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.MalformedURLException
import java.net.URI
import java.net.URISyntaxException
import java.net.URL
import java.net.UnknownHostException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

private val log: Logger = LoggerFactory.getLogger("kz.ncanode.util.Util")
private val revocationLog: Logger = LoggerFactory.getLogger("kz.ncanode.revocation")
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
        URI(trimmed).toURL()
    } catch (e: MalformedURLException) {
        log.warn("Cannot parse url '{}'", trimmed, e)
        null
    } catch (e: URISyntaxException) {
        log.warn("Cannot parse url '{}'", trimmed, e)
        null
    } catch (e: IllegalArgumentException) {
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

/**
 * Минимальный SSRF-барьер для URL, взятых ИЗ сертификата (CRL DP / OCSP AIA):
 * блокирует хосты, которые не бывают легитимными revocation-эндпойнтами —
 * loopback (127/8, ::1), link-local (169.254/16, включая cloud-metadata
 * 169.254.169.254, и fe80::/10), wildcard (0.0.0.0). Site-local/RFC1918
 * НЕ блокируем: приватный внутренний PKI — легитимный кейс (для его отсечения
 * есть strict-режим).
 *
 * Резолвит хост один раз; это best-effort — от DNS-rebinding (хост резолвится
 * в публичный IP здесь, но в приватный на этапе соединения) полноценно не
 * защищает. Для гарантий используйте strict-режим (только конфиг-URL).
 * Если хост не резолвится — не блокируем: последующий запрос сам упадёт
 * с IOException (→ UNAVAILABLE).
 */
fun isInternalHost(url: URL): Boolean = try {
    val addr = InetAddress.getByName(url.host)
    addr.isLoopbackAddress || addr.isLinkLocalAddress || addr.isAnyLocalAddress
} catch (e: UnknownHostException) {
    false
}

/**
 * Пишет WARN, если верификация выполняется БЕЗ проверки отзыва (клиент не
 * передал `revocationCheck`). Отозванный, но в остальном валидный сертификат
 * в этом случае пройдёт как valid — оператор должен видеть это в логах.
 * revocationCheck намеренно opt-in (upstream-совместимость), поэтому это
 * WARN-предупреждение, а не отказ.
 */
fun warnIfRevocationDisabled(checkOcsp: Boolean, checkCrl: Boolean) {
    if (!checkOcsp && !checkCrl) {
        revocationLog.warn(
            "Verification performed WITHOUT revocation check (revocationCheck is empty): " +
                "a revoked certificate will still pass as valid. " +
                "Pass revocationCheck=[\"OCSP\",\"CRL\"] to enable revocation checking.",
        )
    }
}
