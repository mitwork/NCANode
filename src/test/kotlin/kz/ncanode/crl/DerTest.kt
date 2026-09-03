package kz.ncanode.crl

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.nio.ByteBuffer
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * Потоковый DER-ридер, на котором держится индекс CRL.
 *
 * Разбираемые байты приходят из сети: боевой CRL качается по HTTP и может
 * оказаться обрезанным, а то и подложенным. Поэтому проверяется не только
 * «правильное читается правильно», но и что на кривом входе ридер падает
 * своим [DerException] с внятным текстом, а не `IndexOutOfBoundsException`
 * из глубины разбора — по такому исключению вызывающий не отличит битый
 * файл от собственной ошибки.
 */
class DerTest : FunSpec({

    fun buffer(vararg bytes: Int) = ByteBuffer.wrap(ByteArray(bytes.size) { bytes[it].toByte() })

    test("a short-form element gives its tag, content offset and length") {
        val tlv = Der.header(buffer(0x02, 0x01, 0x05), 0)

        tlv.tag shouldBe Der.INTEGER
        tlv.contentOffset shouldBe 2
        tlv.length shouldBe 1
        tlv.end shouldBe 3
        tlv.totalLength shouldBe 3
    }

    test("a long-form length is read from its length bytes") {
        val content = ByteArray(256) { 0x41 }
        val buf = ByteBuffer.wrap(byteArrayOf(0x04, 0x82.toByte(), 0x01, 0x00) + content)

        val tlv = Der.header(buf, 0)

        tlv.length shouldBe 256
        tlv.contentOffset shouldBe 4
        Der.bytes(buf, tlv.contentOffset, tlv.length).size shouldBe 256
    }

    test("encodings that are BER but not DER are refused") {
        // Неопределённая длина и многобайтовые теги в DER запрещены, а в CRL
        // не встречаются вовсе — угадывать тут нечего.
        shouldThrow<DerException> { Der.header(buffer(0x30, 0x80), 0) }
            .message.orEmpty() shouldContain "Indefinite-length"
        shouldThrow<DerException> { Der.header(buffer(0x1F, 0x01, 0x00), 0) }
            .message.orEmpty() shouldContain "Multi-byte"
    }

    test("a length that does not fit into the file is refused") {
        shouldThrow<DerException> { Der.header(buffer(0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05), 0) }
            .message.orEmpty() shouldContain "5 bytes"
        shouldThrow<DerException> { Der.header(buffer(0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF), 0) }
            .message.orEmpty() shouldContain "addressable range"
    }

    test("a truncated element is refused instead of read past the end") {
        shouldThrow<DerException> { Der.header(buffer(0x02, 0x05, 0x01), 0) }
            .message.orEmpty() shouldContain "Truncated DER"
        shouldThrow<DerException> { Der.header(buffer(0x02), 0) }
        shouldThrow<DerException> { Der.bytes(buffer(0x01, 0x02), 1, 5) }
        shouldThrow<DerException> { Der.bytes(buffer(0x01, 0x02), -1, 1) }
    }

    test("both Time forms are read, and a two-digit year pivots at 50") {
        fun time(text: String, tag: Int): Long {
            val buf = ByteBuffer.wrap(byteArrayOf(tag.toByte(), text.length.toByte()) + text.toByteArray())
            return Der.time(buf, Der.header(buf, 0))
        }

        fun expected(year: Int) = LocalDateTime.of(year, 9, 3, 12, 0, 0).toInstant(ZoneOffset.UTC).toEpochMilli()

        time("260903120000Z", Der.UTC_TIME) shouldBe expected(2026)
        // RFC 5280 §4.1.2.5.1: YY >= 50 — это прошлый век.
        time("990903120000Z", Der.UTC_TIME) shouldBe expected(1999)
        time("20260903120000Z", Der.GENERALIZED_TIME) shouldBe expected(2026)
    }

    test("a Time value outside what RFC 5280 allows is refused") {
        fun time(text: String, tag: Int = Der.UTC_TIME) {
            val buf = ByteBuffer.wrap(byteArrayOf(tag.toByte(), text.length.toByte()) + text.toByteArray())
            Der.time(buf, Der.header(buf, 0))
        }

        // Не Time вовсе.
        shouldThrow<DerException> { time("0501", Der.INTEGER) }.message.orEmpty() shouldContain "Not a Time tag"
        // Без секунд и без Z — форма, которую §4.1.2.5 не разрешает.
        shouldThrow<DerException> { time("2609031200Z") }.message.orEmpty() shouldContain "Non-conforming"
        shouldThrow<DerException> { time("260903120000+0600") }.message.orEmpty() shouldContain "Non-conforming"
        // Цифры не цифры.
        shouldThrow<DerException> { time("AA0903120000Z") }.message.orEmpty() shouldContain "Non-numeric year"
        shouldThrow<DerException> { time("26XX03120000Z") }.message.orEmpty() shouldContain "Non-numeric field"
        // Дата, которой не существует.
        shouldThrow<DerException> { time("261303120000Z") }.message.orEmpty() shouldContain "Invalid Time value"
    }

    test("an object identifier is read back in dotted form") {
        // 1.2.840.113549 — первый байт кодирует сразу две дуги.
        val buf = buffer(0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D)

        Der.oid(buf, Der.header(buf, 0)) shouldBe "1.2.840.113549"
    }

    test("a broken object identifier is refused") {
        val empty = buffer(0x06, 0x00)
        shouldThrow<DerException> { Der.oid(empty, Der.header(empty, 0)) }
            .message.orEmpty() shouldContain "Empty"

        // Последний байт с продолжением: дуга оборвана на середине.
        val truncated = buffer(0x06, 0x02, 0x2A, 0x86)
        shouldThrow<DerException> { Der.oid(truncated, Der.header(truncated, 0)) }
            .message.orEmpty() shouldContain "Truncated"
    }
})
