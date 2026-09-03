package kz.ncanode.service

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTCreator
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.exceptions.JWTVerificationException
import kz.ncanode.dto.request.JwtDecodeBatchRequest
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeBatchRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.dto.response.JwtDecodeBatchResponse
import kz.ncanode.dto.response.JwtDecodeResponse
import kz.ncanode.dto.response.JwtEncodeBatchResponse
import kz.ncanode.dto.response.JwtEncodeResponse
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.mapPartial
import kz.ncanode.util.signingAlgorithm
import kz.ncanode.util.verificationAlgorithm
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

            val algorithm = signingAlgorithm(
                jwtEncodeRequest.jwt.header.alg,
                cert.publicKey,
                keystore.privateKey,
            )

            return JwtEncodeResponse(jwt = builder.sign(algorithm))
        } catch (e: ApplicationException) {
            // ClientException из resolveAlgorithm (unsupported alg / не тот тип
            // ключа) — 400, а не 500.
            throw e
        } catch (e: KeyException) {
            throw ClientException(e.message, e)
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Batch-кодирование JWT: каждый header+payload в [JwtEncodeBatchRequest.jwts]
     * подписывается общим ключом. Partial-response per item.
     */
    fun encodeBatch(request: JwtEncodeBatchRequest): JwtEncodeBatchResponse {
        val items = request.jwts.mapPartial({ status, message ->
            JwtEncodeBatchResponse.Item(status = status, message = message)
        }) { jwt ->
            val itemRequest = JwtEncodeRequest().apply {
                this.jwt = jwt
                this.key = request.key
                this.password = request.password
                this.keyAlias = request.keyAlias
            }
            JwtEncodeBatchResponse.Item(jwt = encode(itemRequest).jwt)
        }
        return JwtEncodeBatchResponse(results = items)
    }

    /**
     * Batch-декодирование JWT: каждый токен в [JwtDecodeBatchRequest.jwts]
     * проверяется общим сертификатом. Ошибка верификации одного токена
     * не валит остальных.
     */
    fun decodeBatch(request: JwtDecodeBatchRequest): JwtDecodeBatchResponse {
        val items = request.jwts.mapPartial({ status, message ->
            JwtDecodeResponse(valid = false, status = status, message = message)
        }) { token ->
            decode(JwtDecodeRequest().apply {
                this.jwt = token
                this.key = request.key
            })
        }
        return JwtDecodeBatchResponse(results = items)
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

            val algorithm = verificationAlgorithm(data.algorithm, x509.publicKey)

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

            return JwtDecodeResponse(
                valid = valid,
                jwt = JwtDecodeResponse.Jwt(header = header, payload = payload),
            )
        } catch (e: ClientException) {
            throw e
        } catch (e: Exception) {
            throw ClientException(e.message, e)
        }
    }

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
