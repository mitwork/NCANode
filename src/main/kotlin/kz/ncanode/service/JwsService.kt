package kz.ncanode.service

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.exceptions.JWTVerificationException
import kz.ncanode.dto.jws.JwsSignerInfo
import kz.ncanode.dto.request.JwsSignRequest
import kz.ncanode.dto.request.JwsSignerRequest
import kz.ncanode.dto.request.JwsVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.response.JwsSignResponse
import kz.ncanode.dto.response.JwsVerifyResponse
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.signingAlgorithm
import kz.ncanode.util.verificationAlgorithm
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.node.ArrayNode
import tools.jackson.databind.node.ObjectNode
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * JWS в формате JSON Serialization (RFC 7515 §7.2).
 *
 * Компактной формы здесь нет намеренно: она вмещает ровно одну подпись, а
 * несколько подписантов на один документ — основной сценарий, ради которого
 * JWS и берут. В отличие от XML, добавление подписи здесь ничего не ломает по
 * устройству формата: каждая подпись покрывает свой заголовок и общий payload,
 * а не документ целиком.
 *
 * Сертификат подписанта кладётся в заголовок `x5c` — тогда проверяющей стороне
 * не нужно искать его отдельно, и `verify` работает по одному только JWS.
 */
@Service
class JwsService(
    private val kalkanWrapper: KalkanWrapper,
    private val certificateService: CertificateService,
) {

    /** Подписывает [JwsSignRequest.payload], создавая новый JWS. */
    fun sign(request: JwsSignRequest): JwsSignResponse = build(request, existing = null)

    /**
     * Добавляет подпись к готовому JWS.
     *
     * Отдельный метод, а не флаг: подписант «вторым по маршруту» не переподписывает
     * документ, а дописывает свою подпись рядом с чужой.
     */
    fun addSigners(request: JwsSignRequest): JwsSignResponse {
        val existing = request.jws as? ObjectNode
            ?: throw ClientException("jws must be a JSON object in JSON Serialization form")
        return build(request, existing)
    }

    /**
     * Проверяет все подписи JWS.
     *
     * Вердикт по каждой отдельно: в документе с несколькими подписантами общий
     * флаг не говорит, чья подпись не сошлась.
     */
    fun verify(request: JwsVerifyRequest): JwsVerifyResponse {
        val jws = request.jws as? ObjectNode
            ?: throw ClientException("jws must be a JSON object in JSON Serialization form")

        val payloadEncoded = payloadOf(jws, request.payload)
        val signatures = signaturesOf(jws)
        if (signatures.isEmpty()) {
            throw ClientException("JWS contains no signatures")
        }

        var valid = true
        val signers = signatures.map { entry ->
            val info = verifySignature(entry, payloadEncoded, request.checkOcsp, request.checkCrl)
            if (!info.valid) valid = false
            info
        }

        return JwsVerifyResponse(
            valid = valid,
            signers = signers,
            payload = decodePayload(payloadEncoded),
        )
    }

    private fun build(request: JwsSignRequest, existing: ObjectNode?): JwsSignResponse {
        val payloadEncoded = when {
            existing != null -> payloadOf(existing, request.payload)
            request.payload != null -> encode(mapper.writeValueAsBytes(request.payload))
            else -> throw ClientException("payload must be specified")
        }

        val signatures = mapper.createArrayNode()
        existing?.let { signaturesOf(it).forEach { entry -> signatures.add(entry) } }

        return try {
            for (signer in request.signers) {
                signatures.add(signature(signer, payloadEncoded, request.typ))
            }

            val result = mapper.createObjectNode()
            // Detached: payload в результат не кладём, но подписан он тот же —
            // проверяющей стороне его нужно будет передать отдельно.
            if (!request.detached) {
                result.put("payload", payloadEncoded)
            }
            result.set("signatures", signatures)

            JwsSignResponse(jws = result)
        } catch (e: ApplicationException) {
            throw e
        } catch (e: Exception) {
            throw ServerException("Error signing JWS: ${e.message}", e)
        }
    }

    /** Одна подпись: protected-заголовок и значение подписи над ним и payload. */
    private fun signature(signer: JwsSignerRequest, payloadEncoded: String, typ: String?): ObjectNode {
        val keyStore = kalkanWrapper.read(
            listOf(
                SignerRequest().apply {
                    key = signer.key
                    password = signer.password
                    keyAlias = signer.keyAlias
                },
            ),
        )[0]
        val certificate = keyStore.certificate.x509Certificate

        val header = mapper.createObjectNode().apply {
            put("alg", signer.alg)
            put("typ", typ ?: DEFAULT_TYP)
            // x5c по RFC 7515 §4.1.6 — обычный Base64, не base64url.
            set(
                "x5c",
                mapper.createArrayNode().add(Base64.getEncoder().encodeToString(certificate.encoded)),
            )
        }
        val headerEncoded = encode(mapper.writeValueAsBytes(header))

        val algorithm = signingAlgorithm(signer.alg, certificate.publicKey, keyStore.privateKey)
        val signed = algorithm.sign(signingInput(headerEncoded, payloadEncoded))

        return mapper.createObjectNode().apply {
            put("protected", headerEncoded)
            put("signature", encode(signed))
        }
    }

    private fun verifySignature(
        entry: ObjectNode,
        payloadEncoded: String,
        checkOcsp: Boolean,
        checkCrl: Boolean,
    ): JwsSignerInfo {
        val headerEncoded = entry.get("protected")?.stringValue()
            ?: return JwsSignerInfo(valid = false)

        val header = try {
            mapper.readTree(decode(headerEncoded)) as ObjectNode
        } catch (e: Exception) {
            log.warn("Cannot read the protected header: {}", e.message)
            return JwsSignerInfo(valid = false)
        }
        val headerMap = mapper.convertValue(header, Map::class.java)
            .entries.associate { (key, value) -> key.toString() to value }

        val certificate = certificateOf(header)
            ?: return JwsSignerInfo(valid = false, header = headerMap)

        val alg = header.get("alg")?.stringValue()
            ?: return JwsSignerInfo(valid = false, header = headerMap)

        val wrapper = CertificateWrapper(certificate)
        certificateService.attachValidationData(wrapper, checkOcsp, checkCrl)
        val currentDate = certificateService.getCurrentDate()

        val signatureValid = signatureVerifies(alg, certificate, headerEncoded, payloadEncoded, entry) &&
            wrapper.isValid(currentDate, checkOcsp, checkCrl)

        return JwsSignerInfo(
            valid = signatureValid,
            header = headerMap,
            certificate = wrapper.toCertificateInfo(currentDate, checkOcsp, checkCrl),
        )
    }

    private fun signatureVerifies(
        alg: String,
        certificate: X509Certificate,
        headerEncoded: String,
        payloadEncoded: String,
        entry: ObjectNode,
    ): Boolean {
        val signature = entry.get("signature")?.stringValue() ?: return false
        return try {
            // Проверяем через ту же библиотеку, что подписывала: значение
            // подписи в JOSE лежит в своём формате, и пересобирать его вручную
            // значит повторять её работу с риском разойтись в деталях.
            val algorithm = verificationAlgorithm(alg, certificate.publicKey)
            algorithm.verify(JWT.decode("$headerEncoded.$payloadEncoded.$signature"))
            true
        } catch (e: JWTVerificationException) {
            false
        } catch (e: JWTDecodeException) {
            log.warn("Cannot decode the JWS signature for verification: {}", e.message)
            false
        }
    }

    /** Сертификат подписанта из заголовка `x5c`. */
    private fun certificateOf(header: ObjectNode): X509Certificate? {
        val chain = header.get("x5c") as? ArrayNode ?: return null
        val first = chain.firstOrNull()?.stringValue() ?: return null
        return try {
            CertificateService.load(Base64.getDecoder().decode(first.replace("\\s".toRegex(), "")))
        } catch (e: Exception) {
            log.warn("Cannot read the certificate from the x5c header: {}", e.message)
            null
        }
    }

    private fun payloadOf(jws: ObjectNode, detachedPayload: JsonNode?): String {
        jws.get("payload")?.stringValue()?.let { return it }
        // Detached: подписанного содержимого в документе нет, его приносит клиент.
        return detachedPayload?.let { encode(mapper.writeValueAsBytes(it)) }
            ?: throw ClientException("JWS is detached: payload must be specified")
    }

    /** Подписи из общего или flattened синтаксиса (RFC 7515 §7.2.1–7.2.2). */
    private fun signaturesOf(jws: ObjectNode): List<ObjectNode> {
        (jws.get("signatures") as? ArrayNode)?.let { array ->
            return array.mapNotNull { it as? ObjectNode }
        }
        return if (jws.has("signature")) listOf(jws) else emptyList()
    }

    private fun decodePayload(payloadEncoded: String): JsonNode? = try {
        mapper.readTree(decode(payloadEncoded))
    } catch (e: Exception) {
        log.warn("Cannot read the JWS payload: {}", e.message)
        null
    }

    private fun signingInput(headerEncoded: String, payloadEncoded: String): ByteArray =
        "$headerEncoded.$payloadEncoded".toByteArray(StandardCharsets.US_ASCII)

    private fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    private companion object {
        private val log = LoggerFactory.getLogger(JwsService::class.java)
        private val mapper = ObjectMapper()
        private const val DEFAULT_TYP = "JWT"
    }
}
