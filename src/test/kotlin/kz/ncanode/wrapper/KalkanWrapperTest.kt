package kz.ncanode.wrapper

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ClientException

class KalkanWrapperTest : FunSpec({

    val wrapper = KalkanWrapper(KalkanProvider())

    test("read() with valid p12 returns KeyStoreWrapper") {
        val key = TestResources.loadAsBase64("p12/individual_valid.p12")
        val ks = wrapper.read(key, null, TestResources.P12_PASSWORD)

        ks shouldNotBe null
        ks.aliases shouldNotBe emptyList<String>()
        // Без явного alias выбирается первый из p12.
        ks.alias shouldBe ks.aliases.first()
        ks.password shouldBe TestResources.P12_PASSWORD
    }

    test("read() with wrong password throws KeyException with KEY_INVALID_PASSWORD") {
        val key = TestResources.loadAsBase64("p12/individual_valid.p12")
        val ex = shouldThrow<KeyException> {
            wrapper.read(key, null, "wrong_password")
        }
        ex.message shouldContain "Password incorrect"
    }

    test("read() with invalid base64 throws KeyException with KEY_INVALID_BASE64") {
        val ex = shouldThrow<KeyException> {
            wrapper.read("not-valid-base64-!!!", null, TestResources.P12_PASSWORD)
        }
        ex.message shouldContain "Invalid Base64"
    }

    test("read() with corrupted p12 bytes throws KeyException with KEY_INVALID_FORMAT") {
        // Произвольные не-p12 bytes, корректные как Base64.
        val garbage = java.util.Base64.getEncoder().encodeToString(ByteArray(64) { it.toByte() })
        val ex = shouldThrow<KeyException> {
            wrapper.read(garbage, null, TestResources.P12_PASSWORD)
        }
        ex.message shouldContain "Invalid format"
    }

    test("read() with explicit alias that doesn't exist throws KeyException") {
        val key = TestResources.loadAsBase64("p12/individual_valid.p12")
        val ex = shouldThrow<KeyException> {
            wrapper.read(key, "nonexistent_alias", TestResources.P12_PASSWORD)
        }
        ex.message shouldContain "does not have"
    }

    test("read(List) reads multiple SignerRequest-s into KeyStoreWrappers") {
        val keys = listOf(
            SignerRequest().apply {
                key = TestResources.loadAsBase64("p12/individual_valid.p12")
                password = TestResources.P12_PASSWORD
            },
            SignerRequest().apply {
                key = TestResources.loadAsBase64("p12/legal_ceo_valid.p12")
                password = TestResources.P12_PASSWORD
            },
        )
        val keyStores = wrapper.read(keys)
        keyStores shouldHaveSize 2
        // Каждый KeyStoreWrapper должен дать сертификат.
        keyStores.forEach { it.certificate shouldNotBe null }
    }

    test("read(List) wraps single signer failure with index-aware ClientException (400)") {
        val keys = listOf(
            SignerRequest().apply {
                key = TestResources.loadAsBase64("p12/individual_valid.p12")
                password = TestResources.P12_PASSWORD
            },
            SignerRequest().apply {
                key = TestResources.loadAsBase64("p12/individual_valid.p12")
                password = "wrong"
            },
        )
        // Неверный пароль p12 — ошибка ВХОДА клиента → ClientException (400),
        // не 500 (аудит M1 / CLAUDE.md quirk #22 «400 — плохой p12 пароль»).
        val ex = shouldThrow<ClientException> { wrapper.read(keys) }
        // Сообщение должно включать индекс сломанного signer'а — без него
        // оператор не понимает, какой ключ невалидный в multi-signer запросе.
        ex.message shouldContain "signers[1]"
    }
})

// Локальный inline shouldThrow без зависимости от kotest-assertions-shared.
private inline fun <reified T : Throwable> shouldThrow(block: () -> Unit): T {
    val ex = try {
        block()
        null
    } catch (e: Throwable) {
        e
    }
    require(ex != null) { "Expected ${T::class.simpleName} but no exception was thrown" }
    require(ex is T) {
        "Expected ${T::class.simpleName} but got ${ex::class.simpleName}: ${ex.message}"
    }
    return ex
}
