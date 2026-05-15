package kz.ncanode.util

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.maps.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.slf4j.LoggerFactory

class UtilTest : FunSpec({

    val log = LoggerFactory.getLogger("UtilTest")

    test("sha1 returns 40-char hex of UTF-8 input") {
        sha1("test") shouldBe "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"
        sha1("") shouldBe "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    }

    test("bytesToHex pads each byte to two hex chars uppercase") {
        bytesToHex(byteArrayOf(0x00, 0x0F, 0xFF.toByte())) shouldBe "000FFF"
        bytesToHex(byteArrayOf(0x12, 0x34, 0xAB.toByte(), 0xCD.toByte())) shouldBe "1234ABCD"
    }

    test("createNewUrl parses valid http URL") {
        val url = createNewUrl("http://example.com/path", log)
        url shouldNotBe null
        url!!.host shouldBe "example.com"
    }

    test("createNewUrl returns null for whitespace-corrupted URL (legacy NCA cert quirk)") {
        // Реальный кейс: nca_gost.crt содержал "url1\n URL=url2" — URI.create
        // на этом падает. Util должен молча отбросить.
        createNewUrl("http://crl.pki.gov.kz/foo.crl\n URL=http://other", log) shouldBe null
    }

    test("createNewUrl returns null for null/blank input") {
        createNewUrl(null, log) shouldBe null
    }

    test("urlMap splits whitespace-separated URLs and keys them by sha1") {
        val map = urlMap(
            "http://a.example.com/x http://b.example.com/y",
            log,
        )
        map.size shouldBe 2
        map.values.map { it.host } shouldContainExactlyInAnyOrder listOf("a.example.com", "b.example.com")
    }

    test("urlMap returns empty for null/blank") {
        urlMap(null, log).shouldBeEmpty()
        urlMap("", log).shouldBeEmpty()
        urlMap("   ", log).shouldBeEmpty()
    }

    test("findAllUrls extracts http and https from arbitrary text") {
        val urls = findAllUrls("Visit http://x.test and also https://y.test/path now.")
        urls shouldContainExactlyInAnyOrder listOf("http://x.test", "https://y.test/path")
    }

    test("getDigestAlgorithmOidBYSignAlgorithmOid maps GOST 2015 signature OIDs to digest OIDs") {
        // GOST 2015-256 sig (.2.3.1) -> Streebog-256 digest
        getDigestAlgorithmOidBYSignAlgorithmOid("1.2.398.3.10.1.1.2.3.1") shouldBe "1.2.398.3.10.1.3.2"
        // GOST 2015-512 sig (.2.3.2) -> Streebog-512 digest
        getDigestAlgorithmOidBYSignAlgorithmOid("1.2.398.3.10.1.1.2.3.2") shouldBe "1.2.398.3.10.1.3.3"
    }

    test("getDigestAlgorithmOidBYSignAlgorithmOid falls back to legacy GOST 34.11-95 for unknown OIDs") {
        getDigestAlgorithmOidBYSignAlgorithmOid("9.9.9.9.9.9") shouldBe "1.2.398.3.10.1.3.1"
    }
})
