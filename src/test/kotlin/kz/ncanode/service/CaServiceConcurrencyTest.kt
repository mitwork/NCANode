package kz.ncanode.service

import io.kotest.core.spec.style.FunSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.TestResources
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Регрессия на гонку в [CaService] (аудит H1): геттер `rootCertificates`
 * раньше отдавал живой mutableList, который `updateCache` мутировал через
 * `clear()+addAll()`. Lock-free читатель мог поймать
 * ConcurrentModificationException при итерации либо увидеть транзиентно
 * пустой/неполный список (→ issuer=null → ложный valid:false).
 *
 * Тест стрессует читателей (итерация снапшота — без GOST-крипто, чтобы
 * изолировать именно гонку списка от вопросов thread-safety KalkanProvider)
 * параллельно с писателем, гоняющим `updateCache`. После фикса снапшот
 * неизменяем и публикуется атомарной заменой ссылки: размер всегда полный,
 * итерация не бросает.
 *
 * Требует сети (CA bundle + CA-CRL прогреваются в beforeSpec).
 */
@SpringBootTest
@ActiveProfiles("test")
class CaServiceConcurrencyTest(
    @param:Autowired private val caService: CaService,
    @param:Autowired private val kalkanWrapper: KalkanWrapper,
) : FunSpec({

    extension(SpringExtension)

    beforeSpec {
        // Прогреваем bundle + CA-CRL кэш, чтобы updateCache(false) в writer'е
        // был быстрым (disk + cache hit), без сети на каждой итерации.
        caService.updateCache(true)
    }

    test("concurrent readers of rootCertificates never see a partial snapshot or throw during updateCache") {
        val expectedSize = caService.rootCertificates.size
        expectedSize shouldBe 2 // test bundle: root_test_gost_2022 + nca_gost2022_test

        // Sanity в спокойном состоянии: issuer промежуточного резолвится
        // (end-entity individual_valid выпущен nca_gost2022_test, он в bundle).
        val ks = kalkanWrapper.read(
            TestResources.loadAsBase64("p12/individual_valid.p12"), null, TestResources.P12_PASSWORD,
        )
        caService.getRootCertificateFor(ks.certificate).shouldNotBeNull()

        val errors = ConcurrentLinkedQueue<Throwable>()
        val partialObservations = AtomicInteger(0)
        val stop = AtomicBoolean(false)

        val readers = (1..8).map {
            Thread {
                try {
                    while (!stop.get()) {
                        val snapshot = caService.rootCertificates
                        if (snapshot.size != expectedSize) partialObservations.incrementAndGet()
                        // Итерация должна проходить без ConcurrentModificationException.
                        snapshot.forEach { it.subjectX500Principal }
                    }
                } catch (t: Throwable) {
                    errors.add(t)
                }
            }
        }
        val writer = Thread {
            try {
                repeat(60) { caService.updateCache(false) }
            } catch (t: Throwable) {
                errors.add(t)
            } finally {
                stop.set(true)
            }
        }

        readers.forEach { it.start() }
        writer.start()
        writer.join()
        stop.set(true)
        readers.forEach { it.join(10_000) }

        errors.shouldBeEmpty()
        partialObservations.get() shouldBe 0
    }
})
