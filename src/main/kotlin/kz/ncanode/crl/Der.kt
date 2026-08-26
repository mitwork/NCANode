package kz.ncanode.crl

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * Ошибка разбора DER. Отдельный тип, чтобы вызывающий мог отличить
 * «файл не является корректным CRL» от прочих сбоев ввода-вывода.
 */
class DerException(message: String) : RuntimeException(message)

/**
 * Минимальный DER-ридер поверх [ByteBuffer].
 *
 * Нужен для потокового обхода CRL: штатный `CertificateFactory.generateCRL`
 * материализует КАЖДУЮ запись в объект `X509CRLEntryImpl` (замерено: 604 байта
 * на запись, 243 МБ на боевом `nca_gost_2022.crl` с 422 тыс. записей). Здесь же
 * мы идём по структуре, ничего не аллоцируя, и вытаскиваем ровно то, что нужно
 * индексу.
 *
 * Осознанные ограничения (всё это вне DER и в CRL встречаться не должно):
 *  - неопределённая длина (BER, `0x80`) — отвергается;
 *  - многобайтовые теги (`0x1F`) — отвергаются;
 *  - длина больше 4 байт — отвергается (2 ГБ на CRL нам заведомо хватает).
 *
 * Каждое чтение проверяется по границам буфера: файл может быть обрезан или
 * специально сконструирован, и падать здесь надо предсказуемым [DerException],
 * а не `IndexOutOfBoundsException` из глубины.
 */
internal object Der {

    const val BOOLEAN = 0x01
    const val INTEGER = 0x02
    const val BIT_STRING = 0x03
    const val OCTET_STRING = 0x04
    const val OBJECT_IDENTIFIER = 0x06
    const val ENUMERATED = 0x0A
    const val UTC_TIME = 0x17
    const val GENERALIZED_TIME = 0x18
    const val SEQUENCE = 0x30
    const val CONTEXT_0 = 0xA0

    /** Заголовок TLV: где начинается сам элемент, его тег, где тело и его длина. */
    data class Tlv(val tlvOffset: Int, val tag: Int, val contentOffset: Int, val length: Int) {
        /** Смещение сразу за элементом. */
        val end: Int get() = contentOffset + length

        /** Полная длина элемента вместе с заголовком. */
        val totalLength: Int get() = end - tlvOffset
    }

    /** Читает заголовок TLV по смещению [offset]. */
    fun header(buf: ByteBuffer, offset: Int): Tlv {
        require(offset, 2, buf, "TLV header")
        var p = offset
        val tag = buf.get(p++).toInt() and 0xFF
        if (tag and 0x1F == 0x1F) throw DerException("Multi-byte DER tags are not supported")

        val first = buf.get(p++).toInt() and 0xFF
        val length: Int
        if (first and 0x80 == 0) {
            length = first
        } else {
            val n = first and 0x7F
            if (n == 0) throw DerException("Indefinite-length encoding is not valid DER")
            if (n > 4) throw DerException("DER length of $n bytes is not supported")
            require(p, n, buf, "TLV length")
            var acc = 0L
            for (i in 0 until n) {
                acc = (acc shl 8) or (buf.get(p++).toLong() and 0xFF)
            }
            if (acc > Int.MAX_VALUE) throw DerException("DER length $acc exceeds addressable range")
            length = acc.toInt()
        }
        require(p, length, buf, "TLV content")
        return Tlv(offset, tag, p, length)
    }

    /** Копирует [length] байт с [offset] в новый массив. */
    fun bytes(buf: ByteBuffer, offset: Int, length: Int): ByteArray {
        require(offset, length, buf, "byte range")
        val out = ByteArray(length)
        buf.slice(offset, length).get(out)
        return out
    }

    /**
     * UTCTime / GeneralizedTime в epoch millis.
     *
     * RFC 5280 §4.1.2.5 разрешает в сертификатах и CRL только Z-форму с
     * секундами: `YYMMDDHHMMSSZ` и `YYYYMMDDHHMMSSZ`. Всё остальное (смещения
     * `+hhmm`, дробные секунды, отсутствие секунд) — не конформно, и мы это
     * отвергаем, а не пытаемся угадать.
     */
    fun time(buf: ByteBuffer, tlv: Tlv): Long {
        val text = String(bytes(buf, tlv.contentOffset, tlv.length), StandardCharsets.US_ASCII)
        val yearDigits = when (tlv.tag) {
            UTC_TIME -> 2
            GENERALIZED_TIME -> 4
            else -> throw DerException("Not a Time tag: 0x%02X".format(tlv.tag))
        }
        val expected = yearDigits + 11
        if (text.length != expected || text[expected - 1] != 'Z') {
            throw DerException("Non-conforming Time value \"$text\" (RFC 5280 §4.1.2.5 requires Z-form with seconds)")
        }
        val year = try {
            val head = text.substring(0, yearDigits).toInt()
            // RFC 5280 §4.1.2.5.1: в UTCTime YY >= 50 — это 19YY, иначе 20YY.
            if (yearDigits == 2) (if (head >= 50) 1900 + head else 2000 + head) else head
        } catch (e: NumberFormatException) {
            throw DerException("Non-numeric year in Time value \"$text\"")
        }
        fun part(at: Int): Int = try {
            text.substring(yearDigits + at, yearDigits + at + 2).toInt()
        } catch (e: NumberFormatException) {
            throw DerException("Non-numeric field in Time value \"$text\"")
        }
        return try {
            LocalDateTime.of(year, part(0), part(2), part(4), part(6), part(8))
                .toInstant(ZoneOffset.UTC)
                .toEpochMilli()
        } catch (e: java.time.DateTimeException) {
            throw DerException("Invalid Time value \"$text\": ${e.message}")
        }
    }

    /** OBJECT IDENTIFIER в точечную запись. */
    fun oid(buf: ByteBuffer, tlv: Tlv): String {
        if (tlv.length == 0) throw DerException("Empty OBJECT IDENTIFIER")
        val sb = StringBuilder()
        var value = 0L
        var first = true
        for (i in 0 until tlv.length) {
            val b = buf.get(tlv.contentOffset + i).toInt() and 0xFF
            if (value > (Long.MAX_VALUE shr 7)) throw DerException("OID arc overflow")
            value = (value shl 7) or (b and 0x7F).toLong()
            if (b and 0x80 == 0) {
                if (first) {
                    // Первый байт кодирует сразу две дуги: 40*x + y.
                    val x = minOf(value / 40, 2)
                    sb.append(x).append('.').append(value - 40 * x)
                    first = false
                } else {
                    sb.append('.').append(value)
                }
                value = 0
            }
        }
        if (value != 0L) throw DerException("Truncated OBJECT IDENTIFIER")
        return sb.toString()
    }

    private fun require(offset: Int, length: Int, buf: ByteBuffer, what: String) {
        if (offset < 0 || length < 0 || offset.toLong() + length > buf.limit()) {
            throw DerException("Truncated DER: $what at offset $offset needs $length bytes, limit is ${buf.limit()}")
        }
    }
}
