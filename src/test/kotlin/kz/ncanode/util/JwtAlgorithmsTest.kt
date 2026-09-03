package kz.ncanode.util

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kz.ncanode.exception.ClientException
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

/**
 * Соответствие имён JOSE алгоритмам подписи.
 *
 * Таблица из одних `when`-веток выглядит безобидно ровно до первой опечатки:
 * перепутанные ES384 и ES512 не мешают ни собрать проект, ни подписать — они
 * молча дают подпись не тем алгоритмом, и обнаруживается это у потребителя.
 * Отсюда проверка имени каждого алгоритма и того, что чужой тип ключа
 * отвергается как ошибка клиента, а не падает приведением типа.
 */
class JwtAlgorithmsTest : FunSpec({

    val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    val ec = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    test("RSA algorithms resolve to their JOSE names") {
        listOf("RS256", "RS384", "RS512").forEach { alg ->
            signingAlgorithm(alg, rsa.public, rsa.private).name shouldBe alg
            verificationAlgorithm(alg, rsa.public).name shouldBe alg
        }
    }

    test("EC algorithms resolve to their JOSE names") {
        listOf("ES256", "ES384", "ES512").forEach { alg ->
            signingAlgorithm(alg, ec.public, ec.private).name shouldBe alg
            verificationAlgorithm(alg, ec.public).name shouldBe alg
        }
    }

    test("an unknown algorithm is a client error naming it") {
        val error = shouldThrow<ClientException> { signingAlgorithm("HS256", rsa.public, rsa.private) }
        error.message.orEmpty() shouldContain "HS256"

        shouldThrow<ClientException> { verificationAlgorithm("none", rsa.public) }
    }

    test("a key of the wrong type is a client error, not a ClassCastException") {
        // Клиент прислал RSA-ключ и попросил ES256 — это его ошибка, и она
        // должна называться, а не выглядеть падением сервера.
        shouldThrow<ClientException> { signingAlgorithm("ES256", rsa.public, rsa.private) }
        shouldThrow<ClientException> { verificationAlgorithm("ES256", rsa.public) }
        shouldThrow<ClientException> { signingAlgorithm("RS256", ec.public, ec.private) }
        shouldThrow<ClientException> { verificationAlgorithm("RS256", ec.public) }
    }

    test("GOST algorithms require EC keys too") {
        listOf("GG2015", "GG2004").forEach { alg ->
            shouldThrow<ClientException> { signingAlgorithm(alg, rsa.public, rsa.private) }
        }
    }
})
