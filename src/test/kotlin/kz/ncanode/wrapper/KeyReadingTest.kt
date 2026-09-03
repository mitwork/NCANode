package kz.ncanode.wrapper

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources
import kz.ncanode.exception.ServerException
import kz.ncanode.exception.KeyException
import java.security.KeyStore

/**
 * Чтение ключа из PKCS#12 — то, с чего начинается любая подпись.
 *
 * Здесь важнее обычного, как именно всё ломается: пароль, псевдоним и сам
 * файл приходят от клиента, и разница между «клиент прислал не то» (400) и
 * «у нас сломалось» (500) видна пользователю. Проверяются именно эти границы.
 */
class KeyReadingTest : FunSpec({

    val provider = KalkanProvider()
    val wrapper = KalkanWrapper(provider)
    val key = TestResources.loadAsBase64("p12/individual_valid.p12")

    test("a valid key is read with its aliases") {
        val store = wrapper.read(key, null, TestResources.P12_PASSWORD)

        store.aliases.isNotEmpty() shouldBe true
        store.aliases shouldContain store.alias
        store.certificate.x509Certificate.shouldNotBeNull()
        store.privateKey.shouldNotBeNull()
    }

    test("an explicit alias is honoured, an unknown one is refused") {
        val aliases = wrapper.read(key, null, TestResources.P12_PASSWORD).aliases

        wrapper.read(key, aliases.first(), TestResources.P12_PASSWORD).alias shouldBe aliases.first()

        val error = shouldThrow<KeyException> { wrapper.read(key, "нет такого", TestResources.P12_PASSWORD) }
        error.message.orEmpty() shouldContain "нет такого"
    }

    test("a wrong password is a key error, not a server failure") {
        shouldThrow<KeyException> { wrapper.read(key, null, "неверный") }
    }

    test("data that is not base64 and data that is not a PKCS12 are both key errors") {
        shouldThrow<KeyException> { wrapper.read("не base64 вовсе!", null, TestResources.P12_PASSWORD) }
        shouldThrow<KeyException> { wrapper.read("0J3QtSBwMTI=", null, TestResources.P12_PASSWORD) }
    }

    test("the key error becomes a client error when reading a signer request") {
        // Пароль и файл приходят от клиента: это 400, а не 500 — иначе в
        // batch-обработке чужая опечатка выглядела бы нашей аварией.
        val request = kz.ncanode.dto.request.SignerRequest().apply {
            this.key = key
            this.password = "неверный"
        }

        val error = shouldThrow<kz.ncanode.exception.ClientException> { wrapper.read(listOf(request)) }
        error.message.orEmpty() shouldContain "signers[0]"
    }

    test("an unusable keystore turns library failures into a server error") {
        // Хранилище не загружено: библиотека бросает своё исключение, а наружу
        // должно уйти наше — с понятным сообщением, а не голый KeyStoreException.
        val store = KeyStore.getInstance("PKCS12", provider)
        val broken = KeyStoreWrapper(store, "alias", "password", listOf("alias"))

        shouldThrow<ServerException> { broken.privateKey }
        shouldThrow<ServerException> { broken.certificate }
    }
})
