package kz.ncanode.service

import io.kotest.core.annotation.Condition
import io.kotest.core.annotation.EnabledIf
import io.kotest.core.spec.Spec
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.CadesVerifyRequest
import kz.ncanode.dto.request.PadesVerifyRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import kotlin.reflect.KClass

/**
 * Спека целиком включается только когда эталонные файлы лежат на месте **и**
 * доступна боевая инфраструктура НУЦ.
 *
 * Именно спека, а не отдельные тесты: без этого Spring поднимал бы контекст
 * с боевыми адресами, а `CaService` по `@Scheduled(initialDelay = 0)` тянул бы
 * боевой CA-бандл на каждом прогоне CI — ради тестов, которые всё равно
 * пропущены.
 *
 * Про доступность: эталоны подписаны боевыми ключами, поэтому их проверка
 * опирается на боевые CA и OCSP. Адреса НУЦ отвечают не всегда — наблюдалась
 * тишина дольше любого разумного таймаута. Молчащий сервер — это среда, а не
 * расхождение форматов, и красить им прогон нельзя: иначе первым делом станет
 * непонятно, сломали мы совместимость или просто нет сети.
 */
class ReferenceSignaturesPresent : Condition {
    override fun evaluate(kclass: KClass<out Spec>): Boolean =
        javaClass.classLoader.getResource("ades/cades") != null &&
            SAMPLES.any { javaClass.classLoader.getResource("ades/$it") != null } &&
            productionPkiReachable()

    private fun productionPkiReachable(): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress("pki.gov.kz", 80), REACHABILITY_TIMEOUT_MS)
            true
        }
    } catch (e: IOException) {
        LoggerFactory.getLogger(ReferenceSignaturesPresent::class.java)
            .warn("Skipping the reference signatures: production PKI is unreachable ({})", e.message)
        false
    }

    private companion object {
        val SAMPLES = listOf("cades/b.cms", "xades/b.xml", "pades/b.pdf")
        const val REACHABILITY_TIMEOUT_MS = 3000
    }
}

/**
 * Проверка **эталонных подписей NCALayer** — вторая половина совместимости.
 *
 * Остальные AdES-спеки проверяют наши же подписи roundtrip'ом: они доказывают,
 * что мы читаем собственный формат, но не что мы читаем чужой. Здесь входные
 * данные созданы реализацией НУЦ.
 *
 * Файлов в репозитории нет и, скорее всего, не будет: NCALayer выпускает
 * уровни выше T только боевыми ключами, а боевая подпись — это реальные ИИН и
 * ФИО, которым в публичном репозитории не место. Поэтому каждый тест
 * **пропускается**, если своего файла не нашёл: спека рассчитана на локальный
 * прогон у того, у кого эти подписи есть.
 *
 * Как положить файлы — `src/test/resources/ades/README.md`. Профиль
 * `reference` переключает адреса на боевую иерархию: тестовым бандлом боевую
 * подпись проверить нельзя, цепочка не соберётся.
 */
@SpringBootTest
@ActiveProfiles("test", "reference")
@EnabledIf(ReferenceSignaturesPresent::class)
class AdesReferenceCompatibilityTest(
    @param:Autowired private val cadesService: CadesService,
    @param:Autowired private val xadesService: XadesService,
    @param:Autowired private val padesService: PadesService,
    @param:Autowired private val caService: CaService,
) : FunSpec({

    beforeSpec {
        // Синхронно, иначе первый OCSP-запрос уйдёт раньше загрузки бандла
        // и издатель окажется null (quirk #18).
        caService.updateCache(true)
    }

    /** Содержимое эталонного файла в Base64 либо `null`, если файла нет. */
    fun reference(path: String): String? =
        AdesReferenceCompatibilityTest::class.java.classLoader
            .getResourceAsStream("ades/$path")?.use { Base64.getEncoder().encodeToString(it.readBytes()) }

    val fullCheck = setOf(CertificateRevocation.OCSP, CertificateRevocation.CRL)

    // ---- CAdES ----

    listOf(
        "b.cms" to AdesLevel.B,
        "t.cms" to AdesLevel.T,
        "lt.cms" to AdesLevel.LT,
        "lta.cms" to AdesLevel.LTA,
    ).forEach { (file, expected) ->
        val signature = reference("cades/$file")
        test("CAdES $expected from NCALayer verifies").config(enabled = signature != null) {
            val result = cadesService.verify(
                CadesVerifyRequest().apply {
                    cms = signature!!
                    revocationCheck = fullCheck
                },
            )

            result.valid shouldBe true
            result.level shouldBe expected
            result.verifiedLevel shouldBe expected
        }
    }

    val detached = reference("cades/detached-b.cms")
    val detachedData = reference("cades/detached-data.txt")
    test("detached CAdES from NCALayer verifies against its data")
        .config(enabled = detached != null && detachedData != null) {
            val result = cadesService.verify(
                CadesVerifyRequest().apply {
                    cms = detached!!
                    data = detachedData
                    revocationCheck = fullCheck
                },
            )

            result.valid shouldBe true
        }

    // ---- XAdES ----

    listOf(
        "b.xml" to AdesLevel.B,
        "t.xml" to AdesLevel.T,
        "lt.xml" to AdesLevel.LT,
        "lta.xml" to AdesLevel.LTA,
    ).forEach { (file, expected) ->
        val signature = reference("xades/$file")
        test("XAdES $expected from NCALayer verifies").config(enabled = signature != null) {
            val result = xadesService.verify(
                XadesVerifyRequest().apply {
                    xml = String(Base64.getDecoder().decode(signature!!))
                    revocationCheck = fullCheck
                },
            )

            result.valid shouldBe true
            result.level shouldBe expected
            result.verifiedLevel shouldBe expected
        }
    }

    // ---- PAdES ----

    listOf(
        "b.pdf" to AdesLevel.B,
        "t.pdf" to AdesLevel.T,
        "lt.pdf" to AdesLevel.LT,
        "lta.pdf" to AdesLevel.LTA,
        "visible-b.pdf" to AdesLevel.B,
        "visible-lta.pdf" to AdesLevel.LTA,
    ).forEach { (file, expected) ->
        val signature = reference("pades/$file")
        test("PAdES $file from NCALayer verifies").config(enabled = signature != null) {
            val result = padesService.verify(
                PadesVerifyRequest().apply {
                    pdf = signature!!
                    revocationCheck = fullCheck
                },
            )

            result.valid shouldBe true
            result.level shouldBe expected
            result.verifiedLevel shouldBe expected
        }
    }
})
