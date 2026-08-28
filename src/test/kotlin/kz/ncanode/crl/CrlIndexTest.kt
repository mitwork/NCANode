package kz.ncanode.crl

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.GeneralSecurityException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

/**
 * Проверка [CrlIndex] — компактного индекса отзывов поверх CRL.
 *
 * Главный тест здесь — эквивалентность штатному JDK-парсеру. Индекс строится
 * собственным потоковым обходом DER ([CrlScanner]), написанным ради памяти
 * (243 МБ у `CertificateFactory.generateCRL` против ~12 МБ у индекса на боевом
 * `nca_gost_2022.crl`). Ручной разбор ASN.1 — ровно то место, где ошибка
 * становится дырой в проверке отзыва, поэтому каждая запись реального CRL
 * сверяется с тем, что о ней говорит JDK: серийник, дата, причина. Разойдётся
 * хоть одна — тест красный.
 */
class CrlIndexTest : FunSpec({

    // Инициализирует KalkanProvider: проверка подписи GOST-CRL идёт через него.
    val kalkanProviderName = KalkanProvider.PROVIDER_NAME
    TestResources.loadBytes("crl/nca_gost2022_test.crl")

    val workDir = Files.createTempDirectory("ncanode-crl-index-test").toFile()

    /** Выкладывает test-resource в отдельный каталог, чтобы файлы-спутники не пересекались. */
    fun crlFile(resource: String, label: String): File {
        val dir = File(workDir, label).apply { mkdirs() }
        return File(dir, resource.substringAfterLast('/')).apply {
            writeBytes(TestResources.loadBytes(resource))
        }
    }

    fun parse(file: File): X509CRL =
        CertificateFactory.getInstance("X.509").generateCRL(file.inputStream()) as X509CRL

    fun caCertificate(resource: String): X509Certificate =
        CertificateFactory.getInstance("X.509", kalkanProviderName)
            .generateCertificate(TestResources.loadBytes(resource).inputStream()) as X509Certificate

    test("index reproduces every revocation the JDK parser sees") {
        val file = crlFile("crl/nca_gost2022_test.crl", "equivalence")
        val index = CrlIndex.of(file)
        val reference = parse(file)
        val entries = reference.revokedCertificates.orEmpty()

        // Фикстура должна оставаться содержательной: пустой CRL сделал бы
        // проверку эквивалентности вакуумной.
        entries.size shouldBe 54
        index.entryCount shouldBe entries.size

        for (entry in entries) {
            val found = index.find(entry.serialNumber)
            withClue(entry.serialNumber.toString(16)) {
                found.shouldNotBeNull()
                found.revocationDate shouldBe entry.revocationDate
                found.reason shouldBe entry.revocationReason
            }
        }
    }

    test("index does not invent revocations") {
        val file = crlFile("crl/nca_gost2022_test.crl", "absent")
        val index = CrlIndex.of(file)
        val reference = parse(file)
        val revoked = reference.revokedCertificates.orEmpty().map { it.serialNumber }.toSet()

        // Соседние значения вокруг настоящих серийников: двоичный поиск не
        // должен «промахиваться» на границе и отдавать соседа.
        for (serial in revoked) {
            val next = serial.add(BigInteger.ONE)
            if (next !in revoked) index.find(next).shouldBeNull()
            val previous = serial.subtract(BigInteger.ONE)
            if (previous !in revoked) index.find(previous).shouldBeNull()
        }
        index.find(BigInteger.ONE).shouldBeNull()
        // Нулевой и отрицательный серийники невозможны по RFC 5280 §4.1.2.2.
        index.find(BigInteger.ZERO).shouldBeNull()
        index.find(BigInteger.valueOf(-1)).shouldBeNull()
    }

    test("index exposes the same metadata as the JDK parser") {
        val file = crlFile("crl/nca_gost2022_test.crl", "metadata")
        val index = CrlIndex.of(file)
        val reference = parse(file)

        index.issuer shouldBe reference.issuerX500Principal
        index.thisUpdate shouldBe reference.thisUpdate
        index.nextUpdate shouldBe reference.nextUpdate
        index.criticalExtensionOids shouldBe reference.criticalExtensionOIDs.orEmpty()
        index.unusableReason.shouldBeNull()
        index.isDelta shouldBe false
        index.baseCrlNumber.shouldBeNull()
        index.crlNumber shouldBe crlNumberOf(reference)
    }

    test("delta CRL is recognised and carries its base number") {
        val file = crlFile("crl/nca_gost2022_d_test.crl", "delta")
        val index = CrlIndex.of(file)
        val reference = parse(file)

        index.isDelta shouldBe true
        index.baseCrlNumber shouldBe baseCrlNumberOf(reference)
        index.crlNumber shouldBe crlNumberOf(reference)
        // deltaCRLIndicator помечен critical — это единственное critical-расширение,
        // которое CrlService умеет обрабатывать (RFC 5280 §5.2.4).
        index.criticalExtensionOids shouldBe setOf("2.5.29.27")
        // В фикстуре delta пустая — записей нет вовсе (revokedCertificates отсутствует).
        index.entryCount shouldBe 0
        index.find(BigInteger.TEN).shouldBeNull()
    }

    test("verifies the CRL signature against the issuer public key") {
        val file = crlFile("crl/nca_gost2022_test.crl", "signature")
        val index = CrlIndex.of(file)
        val issuer = caCertificate("ca/nca_gost2022_test.cer")

        // Не бросает — подпись GOST сходится, алгоритм найден по OID из CRL.
        index.verifySignature(issuer.publicKey)
    }

    test("rejects the CRL signature when the key belongs to another CA") {
        val file = crlFile("crl/nca_gost2022_test.crl", "signature-foreign")
        val index = CrlIndex.of(file)
        val foreign = caCertificate("ca/root_test_gost_2022.cer")

        shouldThrow<GeneralSecurityException> { index.verifySignature(foreign.publicKey) }
    }

    test("writes a sidecar next to the CRL and reuses it") {
        val file = crlFile("crl/nca_gost2022_test.crl", "sidecar")
        val sidecar = CrlIndex.indexFileFor(file)
        sidecar.exists() shouldBe false

        CrlIndex.of(file)
        sidecar.isFile shouldBe true
        val builtAt = sidecar.lastModified()
        val size = sidecar.length()

        // Файл-спутник для 54 записей должен быть заметно меньше исходного CRL.
        (size < file.length()) shouldBe true

        // Повторное открытие переиспользует готовый файл — он не переписывается.
        val again = CrlIndex.of(file)
        sidecar.lastModified() shouldBe builtAt
        again.entryCount shouldBe 54
    }

    test("rebuilds the sidecar when the CRL is replaced") {
        val file = crlFile("crl/nca_gost2022_test.crl", "replaced")
        CrlIndex.of(file).entryCount shouldBe 54

        // Подменяем CRL другим (delta, записей нет) — индекс обязан
        // перестроиться, иначе проверка отзыва работала бы по устаревшим данным.
        file.writeBytes(TestResources.loadBytes("crl/nca_gost2022_d_test.crl"))
        file.setLastModified(System.currentTimeMillis() + 1000)

        val rebuilt = CrlIndex.of(file)
        rebuilt.entryCount shouldBe 0
        rebuilt.isDelta shouldBe true
    }

    test("rebuilds a corrupted sidecar instead of failing") {
        val file = crlFile("crl/nca_gost2022_test.crl", "corrupted")
        CrlIndex.of(file)

        CrlIndex.indexFileFor(file).writeBytes(ByteArray(200) { 0x7F })

        val recovered = CrlIndex.of(file)
        recovered.entryCount shouldBe 54
        recovered.issuer shouldBe parse(file).issuerX500Principal
    }

    test("rejects a file that is not a CRL") {
        val dir = File(workDir, "garbage").apply { mkdirs() }

        val garbage = File(dir, "garbage.crl").apply { writeBytes("this is not a CRL".toByteArray()) }
        shouldThrow<DerException> { CrlIndex.of(garbage) }

        val empty = File(dir, "empty.crl").apply { writeBytes(ByteArray(0)) }
        shouldThrow<DerException> { CrlIndex.of(empty) }

        // Обрезанный DER: заголовок обещает больше данных, чем есть в файле.
        val truncated = File(dir, "truncated.crl").apply {
            writeBytes(TestResources.loadBytes("crl/nca_gost2022_test.crl").copyOf(64))
        }
        shouldThrow<DerException> { CrlIndex.of(truncated) }
    }
})

private fun crlNumberOf(crl: X509CRL): BigInteger? = integerExtension(crl, "2.5.29.20")

private fun baseCrlNumberOf(crl: X509CRL): BigInteger? = integerExtension(crl, "2.5.29.27")

/** Читает INTEGER-расширение через JDK — независимая от [CrlScanner] опора для сверки. */
private fun integerExtension(crl: X509CRL, oid: String): BigInteger? {
    val raw = crl.getExtensionValue(oid) ?: return null
    val octets = org.bouncycastle.asn1.ASN1OctetString.getInstance(raw).octets
    return org.bouncycastle.asn1.ASN1Integer.getInstance(octets).value
}
