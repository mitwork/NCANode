@file:JvmName("JwtAlgorithms")

package kz.ncanode.util

import com.auth0.jwt.algorithms.Algorithm
import kz.ncanode.exception.ClientException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * Алгоритмы JOSE, общие для JWT и JWS.
 *
 * `GG2015` и `GG2004` — ГОСТ-алгоритмы из сборки НУЦ; остальные стандартные.
 * Неизвестное имя или ключ не того типа — ошибка клиента: подобрать другой
 * ключ мы за него не можем.
 */
fun signingAlgorithm(alg: String, publicKey: PublicKey, privateKey: PrivateKey): Algorithm = when (alg) {
    "GG2015" -> Algorithm.GG2015(ecPublic(alg, publicKey), ecPrivate(alg, privateKey))
    "GG2004" -> Algorithm.GG2004(ecPublic(alg, publicKey), ecPrivate(alg, privateKey))
    "ES256" -> Algorithm.ECDSA256(ecPublic(alg, publicKey), ecPrivate(alg, privateKey))
    "ES384" -> Algorithm.ECDSA384(ecPublic(alg, publicKey), ecPrivate(alg, privateKey))
    "ES512" -> Algorithm.ECDSA512(ecPublic(alg, publicKey), ecPrivate(alg, privateKey))
    "RS256" -> Algorithm.RSA256(rsaPublic(alg, publicKey), rsaPrivate(alg, privateKey))
    "RS384" -> Algorithm.RSA384(rsaPublic(alg, publicKey), rsaPrivate(alg, privateKey))
    "RS512" -> Algorithm.RSA512(rsaPublic(alg, publicKey), rsaPrivate(alg, privateKey))
    else -> throw ClientException("Unsupported algorithm: $alg")
}

fun verificationAlgorithm(alg: String, publicKey: PublicKey): Algorithm = when (alg) {
    "GG2015" -> Algorithm.GG2015(ecPublic(alg, publicKey))
    "GG2004" -> Algorithm.GG2004(ecPublic(alg, publicKey))
    "ES256" -> Algorithm.ECDSA256(ecPublic(alg, publicKey))
    "ES384" -> Algorithm.ECDSA384(ecPublic(alg, publicKey))
    "ES512" -> Algorithm.ECDSA512(ecPublic(alg, publicKey))
    "RS256" -> Algorithm.RSA256(rsaPublic(alg, publicKey))
    "RS384" -> Algorithm.RSA384(rsaPublic(alg, publicKey))
    "RS512" -> Algorithm.RSA512(rsaPublic(alg, publicKey))
    else -> throw ClientException("Unsupported algorithm: $alg")
}

private fun ecPublic(alg: String, key: PublicKey): ECPublicKey = key as? ECPublicKey
    ?: throw ClientException("Algorithm $alg requires an EC public key, got ${key.javaClass.simpleName}")

private fun ecPrivate(alg: String, key: PrivateKey): ECPrivateKey = key as? ECPrivateKey
    ?: throw ClientException("Algorithm $alg requires an EC private key, got ${key.javaClass.simpleName}")

private fun rsaPublic(alg: String, key: PublicKey): RSAPublicKey = key as? RSAPublicKey
    ?: throw ClientException("Algorithm $alg requires an RSA public key, got ${key.javaClass.simpleName}")

private fun rsaPrivate(alg: String, key: PrivateKey): RSAPrivateKey = key as? RSAPrivateKey
    ?: throw ClientException("Algorithm $alg requires an RSA private key, got ${key.javaClass.simpleName}")
