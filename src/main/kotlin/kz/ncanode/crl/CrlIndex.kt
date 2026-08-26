package kz.ncanode.crl

import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.CRLReason
import java.util.Arrays
import java.util.Date
import javax.security.auth.x500.X500Principal

/** Запись об отзыве: то немногое, что нужно от `X509CRLEntry`. */
data class RevokedEntry(val revocationDate: Date, val reason: CRLReason?)

/**
 * Компактный индекс отозванных серийников поверх CRL.
 *
 * Зачем: штатный `CertificateFactory.generateCRL` держит каждую запись
 * отдельным объектом — на боевом `nca_gost_2022.crl` (20.8 МБ, 422 065 записей)
 * это 243 МБ кучи, замерено. Держать это постоянно в памяти — а именно так
 * работал прежний in-memory кэш CrlService — означало, что один CRL составлял
 * практически весь heap сервиса.
 *
 * Здесь CRL один раз обходится потоково ([CrlScanner]) и раскладывается в
 * плоский бинарный файл-спутник `<имя>.crl.idx`: отсортированная таблица
 * серийников фиксированного шага + параллельные массивы дат и причин. Файл
 * отображается в память (`mmap`), поэтому:
 *
 *  - в куче не лежит ничего, кроме метаданных — страницы file-backed, их
 *    вытесняет ОС под давлением, они не считаются в `-Xmx`;
 *  - индекс переживает рестарт: прогрев после первого запуска не нужен;
 *  - поиск — двоичный по отсортированной таблице, ~20 сравнений.
 *
 * Инвалидация — по длине и mtime исходного `.crl`: не сошлось, файл повреждён
 * или формат другой версии — индекс перестраивается.
 *
 * Замечание про POSIX: обновление индекса делается атомарной подменой файла,
 * поэтому уже отображённые страницы старого индекса остаются валидными до тех
 * пор, пока на них есть ссылки (старый inode жив). На Windows подмена
 * отображённого файла не сработала бы — целевая платформа Docker/Linux.
 */
class CrlIndex private constructor(
    /** Исходный `.crl`, из которого построен индекс. */
    val sourceFile: File,
    private val buffer: ByteBuffer,
    val issuer: X500Principal,
    val thisUpdate: Date,
    val nextUpdate: Date?,
    val crlNumber: BigInteger?,
    val baseCrlNumber: BigInteger?,
    val criticalExtensionOids: Set<String>,
    val entryCount: Int,
    /**
     * Не-null, если CRL нельзя использовать для проверки отзыва: indirect CRL
     * либо critical-расширение записи, которого мы не понимаем. Причина —
     * человекочитаемая, идёт в лог.
     */
    val unusableReason: String?,
    private val stride: Int,
    private val serialsOffset: Int,
    private val datesOffset: Int,
    private val reasonsOffset: Int,
    private val tbsOffset: Int,
    private val tbsLength: Int,
    private val signatureAlgorithmOid: String,
    private val signature: ByteArray,
) {

    /** `true`, если это delta-CRL (присутствует `deltaCRLIndicator`). */
    val isDelta: Boolean get() = baseCrlNumber != null

    /**
     * Ищет серийник в индексе. `null` — не отозван.
     *
     * Неположительные серийники не ищутся: RFC 5280 §4.1.2.2 требует
     * положительный, а при сборке индекса такие записи отбрасываются.
     */
    fun find(serial: BigInteger): RevokedEntry? {
        if (serial.signum() <= 0 || entryCount == 0) return null
        val key = padded(serial) ?: return null

        var low = 0
        var high = entryCount - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            val cmp = compareAt(mid, key)
            when {
                cmp < 0 -> low = mid + 1
                cmp > 0 -> high = mid - 1
                else -> return RevokedEntry(
                    revocationDate = Date(buffer.getLong(datesOffset + mid * Long.SIZE_BYTES)),
                    reason = reasonOf(buffer.get(reasonsOffset + mid).toInt()),
                )
            }
        }
        return null
    }

    /**
     * Криптопроверка подписи CRL ключом издателя. Хэшируется диапазон
     * `tbsCertList` прямо в отображённом исходном файле — 20-мегабайтный CRL
     * при этом в кучу не попадает.
     *
     * Алгоритм берётся по OID из самого CRL: Kalkan регистрирует GOST-OID'ы
     * (`1.2.398.3.10.1.1.2.3.2` и др.) как имена алгоритмов, JDK — RSA'шные,
     * так что `Signature.getInstance(oid)` покрывает оба случая. Форма
     * `OID.<...>` не годится: её GOST-провайдер не знает.
     *
     * @throws java.security.GeneralSecurityException если подпись не сходится
     *   или алгоритм недоступен — как у `X509CRL.verify`.
     */
    fun verifySignature(issuerKey: PublicKey) {
        val source = map(sourceFile)
        if (tbsOffset < 0 || tbsLength < 0 || tbsOffset.toLong() + tbsLength > source.limit()) {
            throw SignatureException("CRL ${sourceFile.name} changed underneath its index")
        }
        val verifier = Signature.getInstance(signatureAlgorithmOid)
        verifier.initVerify(issuerKey)
        verifier.update(source.slice(tbsOffset, tbsLength))
        if (!verifier.verify(signature)) {
            throw SignatureException("CRL ${sourceFile.name} signature does not verify against issuer key")
        }
    }

    /** Дополняет серийник ведущими нулями до [stride]; null — не помещается. */
    private fun padded(serial: BigInteger): ByteArray? {
        val raw = serial.toByteArray()
        val from = if (raw.size > 1 && raw[0].toInt() == 0) 1 else 0
        val length = raw.size - from
        if (length > stride) return null
        val key = ByteArray(stride)
        raw.copyInto(key, stride - length, from, raw.size)
        return key
    }

    private fun compareAt(index: Int, key: ByteArray): Int {
        val base = serialsOffset + index * stride
        for (i in 0 until stride) {
            val a = buffer.get(base + i).toInt() and 0xFF
            val b = key[i].toInt() and 0xFF
            if (a != b) return a - b
        }
        return 0
    }

    companion object {
        private val log = LoggerFactory.getLogger(CrlIndex::class.java)

        /** Расширение файла-спутника. Не заканчивается на `.crl` — списки CRL его не подхватят. */
        const val INDEX_EXTENSION = ".crl.idx"

        private const val MAGIC = 0x4E435249 // "NCRI"
        private const val FORMAT_VERSION = 1
        private const val FIXED_HEADER_SIZE = 64
        private const val ABSENT = Long.MIN_VALUE

        private val REASONS: Array<CRLReason> = CRLReason.values()

        /**
         * Возвращает индекс для [crlFile]: берёт готовый файл-спутник, если он
         * соответствует исходнику, иначе строит заново.
         *
         * @throws DerException если файл не разбирается как CRL
         * @throws IOException при сбое чтения/записи
         */
        fun of(crlFile: File): CrlIndex {
            val indexFile = indexFileFor(crlFile)
            open(crlFile, indexFile)?.let { return it }

            build(crlFile, indexFile)
            return open(crlFile, indexFile)
                ?: throw IOException("Freshly built CRL index ${indexFile.name} did not validate")
        }

        fun indexFileFor(crlFile: File): File = File(crlFile.parentFile, crlFile.name + ".idx")

        /** Читает готовый индекс; null — отсутствует, устарел или повреждён. */
        private fun open(crlFile: File, indexFile: File): CrlIndex? {
            if (!indexFile.isFile || !indexFile.canRead()) return null
            return try {
                val buffer = map(indexFile)
                if (buffer.limit() < FIXED_HEADER_SIZE) return null
                if (buffer.getInt(0) != MAGIC || buffer.getInt(4) != FORMAT_VERSION) return null

                val entryCount = buffer.getInt(8)
                val stride = buffer.getInt(12)
                if (entryCount < 0 || stride <= 0) return null

                // Индекс привязан к конкретной ревизии CRL: скачали новый —
                // длина и/или mtime разойдутся, индекс перестраивается.
                if (buffer.getLong(16) != crlFile.length() || buffer.getLong(24) != crlFile.lastModified()) {
                    return null
                }

                val bodyOffset = buffer.getInt(56)
                val serialsSize = entryCount.toLong() * stride
                val datesSize = entryCount.toLong() * Long.SIZE_BYTES
                val required = bodyOffset.toLong() + serialsSize + datesSize + entryCount
                if (bodyOffset < FIXED_HEADER_SIZE || required > buffer.limit()) return null

                val reader = VariableReader(buffer, FIXED_HEADER_SIZE)
                val issuer = reader.bytes() ?: return null
                val crlNumber = reader.bytes()
                val baseCrlNumber = reader.bytes()
                val criticalOids = reader.strings()
                val unusableReason = reader.string()
                val signatureAlgorithmOid = reader.string() ?: return null
                val signature = reader.bytes() ?: return null

                val nextUpdateMillis = buffer.getLong(40)

                CrlIndex(
                    sourceFile = crlFile,
                    buffer = buffer,
                    issuer = X500Principal(issuer),
                    thisUpdate = Date(buffer.getLong(32)),
                    nextUpdate = if (nextUpdateMillis == ABSENT) null else Date(nextUpdateMillis),
                    crlNumber = crlNumber?.let { BigInteger(it) },
                    baseCrlNumber = baseCrlNumber?.let { BigInteger(it) },
                    criticalExtensionOids = criticalOids,
                    entryCount = entryCount,
                    unusableReason = unusableReason,
                    stride = stride,
                    serialsOffset = bodyOffset,
                    datesOffset = bodyOffset + serialsSize.toInt(),
                    reasonsOffset = bodyOffset + serialsSize.toInt() + datesSize.toInt(),
                    tbsOffset = buffer.getInt(48),
                    tbsLength = buffer.getInt(52),
                    signatureAlgorithmOid = signatureAlgorithmOid,
                    signature = signature,
                )
            } catch (e: RuntimeException) {
                // Битый или обрезанный индекс — не повод падать: перестроим.
                log.warn("Discarding unreadable CRL index {}: {}", indexFile.name, e.message)
                null
            } catch (e: IOException) {
                log.warn("Cannot read CRL index {}: {}", indexFile.name, e.message)
                null
            }
        }

        /**
         * Строит индекс и атомарно подменяет им прежний.
         *
         * Два прохода по CRL: первый считает записи и максимальную длину
         * серийника (нужен шаг таблицы), второй заполняет массивы. Оба
         * потоковые — в куче живут только сами массивы (для боевого CRL
         * это ~12 МБ против 243 МБ у штатного парсера).
         */
        private fun build(crlFile: File, indexFile: File) {
            val started = System.nanoTime()
            val source = map(crlFile)

            val counted = CrlScanner(source).scan(null)
            val entryCount = counted.entryCount
            val stride = maxOf(counted.maxSerialLength, 1)

            val serials = ByteArray(entryCount * stride)
            val dates = LongArray(entryCount)
            val reasons = ByteArray(entryCount)
            var cursor = 0

            val metadata = CrlScanner(source).scan { serialOffset, serialLength, revocationDate, reasonCode ->
                val at = cursor * stride + (stride - serialLength)
                source.slice(serialOffset, serialLength).get(serials, at, serialLength)
                dates[cursor] = revocationDate
                reasons[cursor] = reasonCode.toByte()
                cursor++
            }

            // Порядок для двоичного поиска. Сортируем перестановку индексов,
            // а не сами записи: сравнение — беззнаковое лексикографическое по
            // выровненным серийникам, что при одинаковом шаге совпадает с
            // числовым.
            val order = Array(entryCount) { it }
            Arrays.sort(order) { a, b ->
                Arrays.compareUnsigned(
                    serials, a * stride, a * stride + stride,
                    serials, b * stride, b * stride + stride,
                )
            }

            val variable = ByteArrayOutputStream().also { raw ->
                DataOutputStream(raw).use { out ->
                    out.writeBlob(metadata.issuer.encoded)
                    out.writeBlob(metadata.crlNumber?.toByteArray())
                    out.writeBlob(metadata.baseCrlNumber?.toByteArray())
                    out.writeStrings(metadata.criticalExtensionOids)
                    out.writeString(metadata.unusableReason)
                    out.writeString(metadata.signatureAlgorithmOid)
                    out.writeBlob(metadata.signature)
                }
            }.toByteArray()

            // Тело выравниваем по 8 байт: дальше по нему читают getLong.
            val bodyOffset = align(FIXED_HEADER_SIZE + variable.size)

            val tmpPath = indexFile.toPath().resolveSibling(indexFile.name + ".tmp")
            try {
                DataOutputStream(Files.newOutputStream(tmpPath).buffered()).use { out ->
                    out.writeInt(MAGIC)
                    out.writeInt(FORMAT_VERSION)
                    out.writeInt(entryCount)
                    out.writeInt(stride)
                    out.writeLong(crlFile.length())
                    out.writeLong(crlFile.lastModified())
                    out.writeLong(metadata.thisUpdate)
                    out.writeLong(metadata.nextUpdate ?: ABSENT)
                    out.writeInt(metadata.tbsOffset)
                    out.writeInt(metadata.tbsLength)
                    out.writeInt(bodyOffset)
                    out.writeInt(0) // резерв под флаги
                    out.write(variable)
                    repeat(bodyOffset - FIXED_HEADER_SIZE - variable.size) { out.write(0) }

                    for (index in order) out.write(serials, index * stride, stride)
                    for (index in order) out.writeLong(dates[index])
                    for (index in order) out.write(reasons[index].toInt())
                }
                try {
                    Files.move(
                        tmpPath, indexFile.toPath(),
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE,
                    )
                } catch (e: AtomicMoveNotSupportedException) {
                    Files.move(tmpPath, indexFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                try {
                    Files.deleteIfExists(tmpPath)
                } catch (e: IOException) {
                    log.debug("Could not remove temporary CRL index {}: {}", tmpPath, e.message)
                }
            }

            log.info(
                "Built CRL index for {}: {} entries, {} skipped, {} ms",
                crlFile.name, entryCount, metadata.skippedEntries, (System.nanoTime() - started) / 1_000_000,
            )
        }

        private fun map(file: File): ByteBuffer =
            FileChannel.open(file.toPath(), StandardOpenOption.READ).use { channel ->
                // Отображение переживает закрытие канала; освобождается сборщиком
                // мусора, когда на буфер не остаётся ссылок.
                channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size())
            }

        private fun align(value: Int): Int = (value + 7) and 7.inv()

        private fun reasonOf(code: Int): CRLReason? = if (code in REASONS.indices) REASONS[code] else null

        // --- сериализация переменной части ---

        private fun DataOutputStream.writeBlob(value: ByteArray?) {
            if (value == null) {
                writeInt(-1)
            } else {
                writeInt(value.size)
                write(value)
            }
        }

        private fun DataOutputStream.writeString(value: String?) =
            writeBlob(value?.toByteArray(StandardCharsets.UTF_8))

        private fun DataOutputStream.writeStrings(values: Collection<String>) {
            writeInt(values.size)
            for (value in values) writeString(value)
        }

        private class VariableReader(private val buffer: ByteBuffer, private var offset: Int) {
            fun bytes(): ByteArray? {
                val size = buffer.getInt(offset)
                offset += Int.SIZE_BYTES
                if (size < 0) return null
                val value = ByteArray(size)
                buffer.slice(offset, size).get(value)
                offset += size
                return value
            }

            fun string(): String? = bytes()?.toString(StandardCharsets.UTF_8)

            fun strings(): Set<String> {
                val count = buffer.getInt(offset)
                offset += Int.SIZE_BYTES
                if (count <= 0) return emptySet()
                val values = LinkedHashSet<String>(count)
                repeat(count) { string()?.let { values.add(it) } }
                return values
            }
        }
    }
}
