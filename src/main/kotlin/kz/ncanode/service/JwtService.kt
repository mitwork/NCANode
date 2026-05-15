package kz.ncanode.service

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTCreator
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.exceptions.JWTVerificationException
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.dto.response.JwtDecodeResponse
import kz.ncanode.dto.response.JwtEncodeResponse
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ServerException
import kz.ncanode.wrapper.KalkanWrapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * JWT Service.
 *
 * Сервис отвечает за всё что связано с JWT.
 */
@Service
class JwtService(private val kalkanWrapper: KalkanWrapper) {

    /**
     * Формирование и подписание JWT.
     */
    fun encode(jwtEncodeRequest: JwtEncodeRequest): JwtEncodeResponse {
        try {
            val keystore = kalkanWrapper.read(
                jwtEncodeRequest.key,
                jwtEncodeRequest.keyAlias,
                jwtEncodeRequest.password,
            )
            val cert = keystore.certificate

            val builder = JWT.create()
            for ((claimKey, claimValue) in jwtEncodeRequest.jwt.payload.claims) {
                addClaim(builder, claimKey, claimValue)
            }

            val algorithm = resolveAlgorithm(
                jwtEncodeRequest.jwt.header.alg,
                cert.publicKey,
                keystore.privateKey,
            )

            return JwtEncodeResponse.builder()
                .jwt(builder.sign(algorithm))
                .build()
        } catch (e: KeyException) {
            throw ClientException(e.message, e)
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Декодирование и проверка JWT.
     */
    fun decode(jwtDecodeRequest: JwtDecodeRequest): JwtDecodeResponse {
        try {
            val x509 = CertificateService.load(
                Base64.getDecoder().decode(jwtDecodeRequest.key.replace("\\s".toRegex(), ""))
            ) ?: throw ClientException("Invalid certificate")

            var valid = true

            val data = try {
                JWT.decode(jwtDecodeRequest.jwt)
            } catch (e: JWTDecodeException) {
                throw ClientException(e.message, e)
            }

            val algorithm = resolveAlgorithm(data.algorithm, x509.publicKey)

            try {
                JWT.require(algorithm).build().verify(jwtDecodeRequest.jwt)
            } catch (e: JWTVerificationException) {
                log.error("JWT Verification Exception", e)
                valid = false
            }

            val payload = linkedMapOf<String, Any?>()
            for ((claimKey, claim) in data.claims) {
                payload[claimKey] = claim.`as`(Any::class.java)
            }

            val header = linkedMapOf<String, String>()
            header["alg"] = data.algorithm
            header["typ"] = data.type

            return JwtDecodeResponse.builder()
                .valid(valid)
                .jwt(
                    JwtDecodeResponse.Jwt.builder()
                        .header(header)
                        .payload(payload)
                        .build()
                )
                .build()
        } catch (e: ClientException) {
            throw e
        } catch (e: Exception) {
            throw ClientException(e.message, e)
        }
    }

    private fun resolveAlgorithm(alg: String, publicKey: PublicKey, privateKey: PrivateKey): Algorithm = when (alg) {
        "GG2015" -> Algorithm.GG2015(ecPub(alg, publicKey), ecPriv(alg, privateKey))
        "GG2004" -> Algorithm.GG2004(ecPub(alg, publicKey), ecPriv(alg, privateKey))
        "ES256" -> Algorithm.ECDSA256(ecPub(alg, publicKey), ecPriv(alg, privateKey))
        "ES384" -> Algorithm.ECDSA384(ecPub(alg, publicKey), ecPriv(alg, privateKey))
        "ES512" -> Algorithm.ECDSA512(ecPub(alg, publicKey), ecPriv(alg, privateKey))
        "RS256" -> Algorithm.RSA256(rsaPub(alg, publicKey), rsaPriv(alg, privateKey))
        "RS384" -> Algorithm.RSA384(rsaPub(alg, publicKey), rsaPriv(alg, privateKey))
        "RS512" -> Algorithm.RSA512(rsaPub(alg, publicKey), rsaPriv(alg, privateKey))
        else -> throw ClientException("Unsupported algorithm: $alg")
    }

    private fun resolveAlgorithm(alg: String, publicKey: PublicKey): Algorithm = when (alg) {
        "GG2015" -> Algorithm.GG2015(ecPub(alg, publicKey))
        "GG2004" -> Algorithm.GG2004(ecPub(alg, publicKey))
        "ES256" -> Algorithm.ECDSA256(ecPub(alg, publicKey))
        "ES384" -> Algorithm.ECDSA384(ecPub(alg, publicKey))
        "ES512" -> Algorithm.ECDSA512(ecPub(alg, publicKey))
        "RS256" -> Algorithm.RSA256(rsaPub(alg, publicKey))
        "RS384" -> Algorithm.RSA384(rsaPub(alg, publicKey))
        "RS512" -> Algorithm.RSA512(rsaPub(alg, publicKey))
        else -> throw ClientException("Unsupported algorithm: $alg")
    }

    private fun ecPub(alg: String, key: PublicKey): ECPublicKey = key as? ECPublicKey
        ?: throw ClientException("Algorithm $alg requires an EC public key, got ${key.javaClass.simpleName}")

    private fun ecPriv(alg: String, key: PrivateKey): ECPrivateKey = key as? ECPrivateKey
        ?: throw ClientException("Algorithm $alg requires an EC private key, got ${key.javaClass.simpleName}")

    private fun rsaPub(alg: String, key: PublicKey): RSAPublicKey = key as? RSAPublicKey
        ?: throw ClientException("Algorithm $alg requires an RSA public key, got ${key.javaClass.simpleName}")

    private fun rsaPriv(alg: String, key: PrivateKey): RSAPrivateKey = key as? RSAPrivateKey
        ?: throw ClientException("Algorithm $alg requires an RSA private key, got ${key.javaClass.simpleName}")

    private fun addClaim(builder: JWTCreator.Builder, key: String, value: Any?) {
        when (value) {
            is String -> builder.withClaim(key, value)
            is Int -> builder.withClaim(key, value)
            is Long -> builder.withClaim(key, value)
            is Double -> builder.withClaim(key, value)
            is Boolean -> builder.withClaim(key, value)
            null -> Unit
            else -> builder.withClaim(key, value.toString())
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(JwtService::class.java)
    }
}
