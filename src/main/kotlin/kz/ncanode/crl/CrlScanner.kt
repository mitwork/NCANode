package kz.ncanode.crl

import java.math.BigInteger
import java.nio.ByteBuffer
import javax.security.auth.x500.X500Principal

/**
 * Потоковый обход CRL (RFC 5280 §5) без материализации записей.
 *
 * Разбирает `CertificateList` ровно настолько, насколько нужно [CrlIndex]:
 * метаданные, диапазон байт `tbsCertList` (для последующей проверки подписи)
 * и — через колбэк — каждую запись об отзыве. Ничего не аллоцирует на запись,
 * поэтому обход боевого 20.8-МБ CRL укладывается в единицы мегабайт кучи
 * против 243 МБ у `CertificateFactory.generateCRL`.
 *
 * ```
 * CertificateList ::= SEQUENCE {
 *     tbsCertList          TBSCertList,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING }
 *
 * TBSCertList ::= SEQUENCE {
 *     version              Version OPTIONAL,
 *     signature            AlgorithmIdentifier,
 *     issuer               Name,
 *     thisUpdate           Time,
 *     nextUpdate           Time OPTIONAL,
 *     revokedCertificates  SEQUENCE OF SEQUENCE {
 *         userCertificate      CertificateSerialNumber,
 *         revocationDate       Time,
 *         crlEntryExtensions   Extensions OPTIONAL } OPTIONAL,
 *     crlExtensions        [0] EXPLICIT Extensions OPTIONAL }
 * ```
 */
internal class CrlScanner(private val buf: ByteBuffer) {

    /**
     * Колбэк на запись об отзыве. Серийник отдаётся как диапазон в исходном
     * буфере — вызывающий копирует его сразу в своё хранилище, промежуточный
     * `ByteArray` на каждую из сотен тысяч записей не создаётся.
     *
     * [reasonCode] — код RFC 5280 §5.3.1, либо -1 если расширения reasonCode
     * нет (что соответствует `X509CRLEntry.getRevocationReason() == null`).
     */
    fun interface EntryHandler {
        fun onEntry(serialOffset: Int, serialLength: Int, revocationDate: Long, reasonCode: Int)
    }

    class Metadata(
        val issuer: X500Principal,
        val thisUpdate: Long,
        val nextUpdate: Long?,
        val crlNumber: BigInteger?,
        val baseCrlNumber: BigInteger?,
        val criticalExtensionOids: Set<String>,
        val tbsOffset: Int,
        val tbsLength: Int,
        val signatureAlgorithmOid: String,
        val signature: ByteArray,
        val entryCount: Int,
        val maxSerialLength: Int,
        val unusableReason: String?,
        val skippedEntries: Int,
    )

    private var entryCount = 0
    private var maxSerialLength = 0
    private var unusableReason: String? = null
    private var skippedEntries = 0

    /**
     * Проходит CRL целиком. [handler] может быть null — тогда записи только
     * пересчитываются (первый проход сборки индекса, где нужны count и
     * максимальная длина серийника).
     */
    fun scan(handler: EntryHandler?): Metadata {
        val outer = Der.header(buf, 0)
        if (outer.tag != Der.SEQUENCE) throw DerException("CertificateList is not a SEQUENCE")

        val tbs = Der.header(buf, outer.contentOffset)
        if (tbs.tag != Der.SEQUENCE) throw DerException("TBSCertList is not a SEQUENCE")

        var p = tbs.contentOffset
        val tbsEnd = tbs.end

        var element = Der.header(buf, p)
        if (element.tag == Der.INTEGER) {                     // version OPTIONAL
            p = element.end
            element = Der.header(buf, p)
        }
        if (element.tag != Der.SEQUENCE) throw DerException("TBSCertList.signature is not an AlgorithmIdentifier")
        p = element.end                                        // signature (дублирует внешний algid)

        element = Der.header(buf, p)
        if (element.tag != Der.SEQUENCE) throw DerException("TBSCertList.issuer is not a Name")
        val issuer = X500Principal(Der.bytes(buf, element.tlvOffset, element.totalLength))
        p = element.end

        element = Der.header(buf, p)
        val thisUpdate = Der.time(buf, element)
        p = element.end

        var nextUpdate: Long? = null
        if (p < tbsEnd) {
            element = Der.header(buf, p)
            if (element.tag == Der.UTC_TIME || element.tag == Der.GENERALIZED_TIME) {
                nextUpdate = Der.time(buf, element)
                p = element.end
            }
        }

        if (p < tbsEnd) {
            element = Der.header(buf, p)
            if (element.tag == Der.SEQUENCE) {                 // revokedCertificates OPTIONAL
                scanEntries(element, handler)
                p = element.end
            }
        }

        var crlNumber: BigInteger? = null
        var baseCrlNumber: BigInteger? = null
        var criticalOids: Set<String> = emptySet()
        if (p < tbsEnd) {
            element = Der.header(buf, p)
            if (element.tag == Der.CONTEXT_0) {                // crlExtensions [0] EXPLICIT
                val extensions = Der.header(buf, element.contentOffset)
                if (extensions.tag != Der.SEQUENCE) throw DerException("crlExtensions is not a SEQUENCE")
                val parsed = scanCrlExtensions(extensions)
                crlNumber = parsed.crlNumber
                baseCrlNumber = parsed.baseCrlNumber
                criticalOids = parsed.criticalOids
            }
        }

        // signatureAlgorithm + signatureValue идут сразу за tbsCertList.
        val algorithm = Der.header(buf, tbs.end)
        if (algorithm.tag != Der.SEQUENCE) throw DerException("signatureAlgorithm is not an AlgorithmIdentifier")
        val algorithmOid = Der.header(buf, algorithm.contentOffset)
        if (algorithmOid.tag != Der.OBJECT_IDENTIFIER) throw DerException("signatureAlgorithm has no OID")

        val signatureBits = Der.header(buf, algorithm.end)
        if (signatureBits.tag != Der.BIT_STRING) throw DerException("signatureValue is not a BIT STRING")
        if (signatureBits.length < 1) throw DerException("Empty signatureValue")
        // Первый байт BIT STRING — количество неиспользуемых бит; в подписи он 0.
        val signature = Der.bytes(buf, signatureBits.contentOffset + 1, signatureBits.length - 1)

        return Metadata(
            issuer = issuer,
            thisUpdate = thisUpdate,
            nextUpdate = nextUpdate,
            crlNumber = crlNumber,
            baseCrlNumber = baseCrlNumber,
            criticalExtensionOids = criticalOids,
            tbsOffset = tbs.tlvOffset,
            tbsLength = tbs.totalLength,
            signatureAlgorithmOid = Der.oid(buf, algorithmOid),
            signature = signature,
            entryCount = entryCount,
            maxSerialLength = maxSerialLength,
            unusableReason = unusableReason,
            skippedEntries = skippedEntries,
        )
    }

    private fun scanEntries(sequence: Der.Tlv, handler: EntryHandler?) {
        var q = sequence.contentOffset
        val end = sequence.end
        while (q < end) {
            val entry = Der.header(buf, q)
            if (entry.tag != Der.SEQUENCE) throw DerException("revokedCertificate entry is not a SEQUENCE")

            val serial = Der.header(buf, entry.contentOffset)
            if (serial.tag != Der.INTEGER) throw DerException("userCertificate is not an INTEGER")
            if (serial.length < 1) throw DerException("Empty userCertificate")

            val date = Der.header(buf, serial.end)
            val revocationDate = Der.time(buf, date)

            var reasonCode = -1
            if (date.end < entry.end) {
                val extensions = Der.header(buf, date.end)
                if (extensions.tag == Der.SEQUENCE) reasonCode = scanEntryExtensions(extensions)
            }

            // RFC 5280 §4.1.2.2 требует положительный серийник. Отрицательный
            // (старший бит первого байта содержимого) пропускаем: иначе его
            // беззнаковая интерпретация могла бы совпасть с серийником
            // настоящего сертификата и ложно объявить его отозванным.
            if (buf.get(serial.contentOffset).toInt() and 0x80 != 0) {
                skippedEntries++
            } else {
                // Ведущий нулевой байт — знаковая набивка DER, в значение не входит.
                var offset = serial.contentOffset
                var length = serial.length
                if (length > 1 && buf.get(offset).toInt() == 0) {
                    offset++
                    length--
                }
                if (length > maxSerialLength) maxSerialLength = length
                entryCount++
                handler?.onEntry(offset, length, revocationDate, reasonCode)
            }

            q = entry.end
        }
    }

    /** Возвращает код reasonCode записи, либо -1 если расширения нет. */
    private fun scanEntryExtensions(extensions: Der.Tlv): Int {
        var reasonCode = -1
        forEachExtension(extensions) { oid, critical, value ->
            when (oid) {
                OID_REASON_CODE -> {
                    val enumerated = Der.header(buf, value.contentOffset)
                    if (enumerated.tag == Der.ENUMERATED && enumerated.length >= 1) {
                        reasonCode = buf.get(enumerated.contentOffset).toInt() and 0xFF
                    }
                }
                // Indirect CRL (RFC 5280 §5.3.3): запись относится к другому
                // издателю, а не к издателю самого CRL. Мы сопоставляем записи
                // по одному только серийнику, поэтому такой CRL целиком
                // помечается непригодным — иначе чужой отзыв приписался бы
                // нашему CA и ложно отозвал валидный сертификат.
                OID_CERTIFICATE_ISSUER -> markUnusable("indirect CRL (certificateIssuer entry extension)")
                // Critical-расширение записи, которого мы не понимаем: смысл
                // записи нам неизвестен, доверять CRL целиком нельзя (§5.3).
                else -> if (critical) markUnusable("unhandled critical entry extension $oid")
            }
        }
        return reasonCode
    }

    /** Первая причина непригодности запоминается и не перетирается последующими. */
    private fun markUnusable(reason: String) {
        if (unusableReason == null) unusableReason = reason
    }

    private class CrlExtensions(
        val crlNumber: BigInteger?,
        val baseCrlNumber: BigInteger?,
        val criticalOids: Set<String>,
    )

    private fun scanCrlExtensions(extensions: Der.Tlv): CrlExtensions {
        var crlNumber: BigInteger? = null
        var baseCrlNumber: BigInteger? = null
        val criticalOids = LinkedHashSet<String>()
        forEachExtension(extensions) { oid, critical, value ->
            if (critical) criticalOids.add(oid)
            if (oid == OID_CRL_NUMBER || oid == OID_DELTA_CRL_INDICATOR) {
                val integer = Der.header(buf, value.contentOffset)
                if (integer.tag == Der.INTEGER && integer.length >= 1) {
                    val number = BigInteger(Der.bytes(buf, integer.contentOffset, integer.length))
                    if (oid == OID_CRL_NUMBER) crlNumber = number else baseCrlNumber = number
                }
            }
        }
        return CrlExtensions(crlNumber, baseCrlNumber, criticalOids)
    }

    /**
     * `Extensions ::= SEQUENCE OF Extension`, где
     * `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
     */
    private inline fun forEachExtension(extensions: Der.Tlv, action: (String, Boolean, Der.Tlv) -> Unit) {
        var p = extensions.contentOffset
        val end = extensions.end
        while (p < end) {
            val extension = Der.header(buf, p)
            if (extension.tag != Der.SEQUENCE) throw DerException("Extension is not a SEQUENCE")
            val id = Der.header(buf, extension.contentOffset)
            if (id.tag != Der.OBJECT_IDENTIFIER) throw DerException("Extension has no extnID")

            var next = Der.header(buf, id.end)
            var critical = false
            if (next.tag == Der.BOOLEAN) {
                critical = next.length >= 1 && buf.get(next.contentOffset).toInt() != 0
                next = Der.header(buf, next.end)
            }
            if (next.tag != Der.OCTET_STRING) throw DerException("Extension has no extnValue")

            action(Der.oid(buf, id), critical, next)
            p = extension.end
        }
    }

    companion object {
        private const val OID_REASON_CODE = "2.5.29.21"
        private const val OID_CERTIFICATE_ISSUER = "2.5.29.29"
        private const val OID_CRL_NUMBER = "2.5.29.20"
        private const val OID_DELTA_CRL_INDICATOR = "2.5.29.27"
    }
}
