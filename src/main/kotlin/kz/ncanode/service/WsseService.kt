package kz.ncanode.service

import jakarta.xml.soap.MessageFactory
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.request.WsseSignBatchRequest
import kz.ncanode.dto.request.WsseSignRequest
import kz.ncanode.dto.request.WsseVerifyBatchRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.WsseSignBatchResponse
import kz.ncanode.dto.response.WsseVerifyBatchResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.mapPartial
import kz.ncanode.util.warnIfRevocationDisabled
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.apache.wss4j.common.bsp.BSPEnforcer
import org.apache.wss4j.common.crypto.CertificateStore
import org.apache.wss4j.common.token.SecurityTokenReference
import org.apache.wss4j.dom.WSConstants
import org.apache.wss4j.dom.message.WSSecHeader
import org.apache.xml.security.c14n.Canonicalizer
import org.apache.xml.security.exceptions.XMLSecurityException
import org.apache.xml.security.signature.XMLSignature
import org.apache.xml.security.transforms.Transforms
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.w3c.dom.Element
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.Date
import java.util.UUID
import javax.xml.namespace.QName
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

/**
 * Сервис для работы с Wsse (SOAP).
 */
@Service
class WsseService(
    private val kalkanWrapper: KalkanWrapper,
    private val xmlService: XmlService,
    private val certificateService: CertificateService,
) {

    /**
     * Подписывает Wsse XML.
     */
    fun sign(wsseSignRequest: WsseSignRequest): XmlSignResponse {
        try {
            val keystore = kalkanWrapper.read(
                wsseSignRequest.key,
                wsseSignRequest.keyAlias,
                wsseSignRequest.password,
            )
            val cert = keystore.certificate

            // sign a soap request according to a reference implementation from smartbridge
            val xmlBytes = xmlService.prepare(wsseSignRequest.xml, wsseSignRequest.isTrimXml)
                .toByteArray(StandardCharsets.UTF_8)
            val msg = MessageFactory.newInstance().createMessage(null, xmlBytes.inputStream())
            val env = msg.soapPart.envelope
            val body = env.body

            val bodyId = "id-${UUID.randomUUID()}"
            body.addAttribute(QName(WSConstants.WSU_NS, "Id", WSConstants.WSU_PREFIX), bodyId)

            val header = env.header ?: env.addHeader()

            val doc = env.ownerDocument

            val transforms = Transforms(doc).apply {
                addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
            }

            val signature = XMLSignatureWrapper(
                doc, cert.signAlgorithmId, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
            )

            signature.xmlSignature.addDocument("#$bodyId", transforms, cert.hashAlgorithmId)

            val secHeader = WSSecHeader(doc).apply {
                setMustUnderstand(true)
                insertSecurityHeader()
            }
            header.appendChild(secHeader.securityHeaderElement)
            header.firstChild.appendChild(signature.xmlSignature.element)

            val reference = SecurityTokenReference(doc).apply {
                setKeyIdentifier(cert.x509Certificate)
            }

            signature.xmlSignature.keyInfo.addUnknownElement(reference.element)
            signature.xmlSignature.sign(keystore.privateKey)

            return StringWriter().use { os ->
                val transformer = TransformerFactory.newInstance().newTransformer()
                transformer.transform(DOMSource(doc), StreamResult(os))
                XmlSignResponse(xml = os.toString())
            }
        } catch (e: ApplicationException) {
            throw e
        } catch (e: KeyException) {
            throw ClientException(e.message, e)
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Batch-подпись: каждый envelope в [WsseSignBatchRequest.xmls] подписывается
     * общим ключом. Partial-response: ошибка на N-м item'е не валит остальные.
     */
    fun signBatch(request: WsseSignBatchRequest): WsseSignBatchResponse {
        val items = request.xmls.mapPartial({ status, message ->
            WsseSignBatchResponse.Item(status = status, message = message)
        }) { xml ->
            val itemRequest = WsseSignRequest().apply {
                this.xml = xml
                this.key = request.key
                this.password = request.password
                this.keyAlias = request.keyAlias
                this.isTrimXml = request.isTrimXml
            }
            WsseSignBatchResponse.Item(xml = sign(itemRequest).xml)
        }
        return WsseSignBatchResponse(results = items)
    }

    /**
     * Проверяет подписанный SOAP-конверт.
     */
    fun verify(xml: String, checkOcsp: Boolean, checkCrl: Boolean): VerificationResponse {
        warnIfRevocationDisabled(checkOcsp, checkCrl)
        try {
            val xmlBytes = xmlService.prepare(xml, false).toByteArray(StandardCharsets.UTF_8)
            val msg = MessageFactory.newInstance().createMessage(null, xmlBytes.inputStream())
            val env = msg.soapPart.envelope
            val doc = env.ownerDocument

            val root = doc.firstChild as Element
            val signatures = root.getElementsByTagName("ds:Signature")
            val signaturesLength = signatures.length

            if (signaturesLength < 1) {
                return VerificationResponse(valid = false, signers = emptyList())
            }

            // SOAP Body, который подпись обязана покрывать. Регистрируем его
            // wsu:Id как ID-атрибут — чтобы Reference "#id" резолвился именно в
            // настоящий Body, а не в одноимённый элемент, подсунутый XSW-атакой
            // (move-original / duplicate-id). Делаем один раз на конверт.
            val bodyEl = env.body as Element
            val bodyId = bodyEl.getAttributeNS(WSConstants.WSU_NS, "Id")
            if (bodyId.isNotEmpty()) {
                bodyEl.setIdAttributeNS(WSConstants.WSU_NS, "Id", true)
            }

            var valid = true
            val certs = mutableListOf<CertificateWrapper>()
            val currentDate = certificateService.getCurrentDate()

            // Каждая ds:Signature проверяется независимо. Сертификат берётся
            // из её собственного wsse:SecurityTokenReference (KeyInfo внутри
            // подписи), а не из первого попавшегося STR во всём конверте —
            // иначе можно было бы перепутать подпись Alice'а с cert'ом Bob'а.
            for (i in 0 until signaturesLength) {
                val sigElement = signatures.item(i) as Element
                // secureValidation=true: блокирует duplicate-id и небезопасные
                // трансформы при checkSignatureValue (XSW-защита).
                val signature = XMLSignature(sigElement, "", true)

                val strInSignature = sigElement.getElementsByTagName("wsse:SecurityTokenReference")
                if (strInSignature.length < 1) {
                    log.warn("WSSE signature #{} has no SecurityTokenReference", i)
                    valid = false
                    continue
                }
                val ref = SecurityTokenReference(strInSignature.item(0) as Element, BSPEnforcer(true))
                val resolved: Array<X509Certificate>? = ref.getKeyIdentifier(CertificateStore(emptyArray()))
                if (resolved == null || resolved.isEmpty()) {
                    log.warn("WSSE signature #{} could not resolve a certificate from STR", i)
                    valid = false
                    continue
                }

                val cert = CertificateWrapper(resolved[0])
                certificateService.attachValidationData(cert, checkOcsp, checkCrl)

                // Битая/подложенная подпись (например, неразрешимый Reference
                // после XSW) должна давать valid=false, а не валить весь запрос
                // исключением.
                val thisOk = try {
                    val cryptoOk = signature.checkSignatureValue(cert.publicKey)
                    // Подпись обязана ссылаться именно на SOAP Body — иначе
                    // checkSignatureValue лишь подтверждает целостность какого-то
                    // под-элемента, а реальный Body может быть неподписан (XSW).
                    val coversBody = bodyId.isNotEmpty() && signatureReferencesId(signature, bodyId)
                    if (!coversBody) {
                        log.warn(
                            "WSSE signature #{} does not cover the SOAP Body — rejecting (possible XML Signature Wrapping)",
                            i,
                        )
                    }
                    cryptoOk && coversBody && cert.isValid(currentDate, checkOcsp, checkCrl)
                } catch (e: XMLSecurityException) {
                    log.warn("WSSE signature #{} verification failed: {}", i, e.message)
                    false
                }
                if (!thisOk) valid = false
                certs.add(cert)
            }

            return VerificationResponse(
                valid = valid,
                signers = certs.map { it.toCertificateInfo(currentDate, checkOcsp, checkCrl) },
            )
        } catch (e: Exception) {
            throw ServerException(e.message, e)
        }
    }

    /**
     * Batch-верификация SOAP envelope'ов. Каждый item проверяется
     * независимо с общими revocation-флагами; на исключение item
     * получает `valid=false` со status/message.
     */
    fun verifyBatch(request: WsseVerifyBatchRequest): WsseVerifyBatchResponse {
        val checkOcsp = request.checkOcsp
        val checkCrl = request.checkCrl
        val items = request.xmls.mapPartial({ status, message ->
            VerificationResponse(valid = false, status = status, message = message)
        }) { xml ->
            verify(xml, checkOcsp, checkCrl)
        }
        return WsseVerifyBatchResponse(results = items)
    }

    /**
     * Ссылается ли подпись хотя бы одним Reference'ом на элемент с данным id
     * (`URI="#id"`). Используется для проверки, что подписан именно SOAP Body.
     */
    private fun signatureReferencesId(signature: XMLSignature, id: String): Boolean = try {
        val signedInfo = signature.signedInfo
        (0 until signedInfo.length).any { signedInfo.item(it).uri == "#$id" }
    } catch (e: XMLSecurityException) {
        false
    }

    companion object {
        private val log = LoggerFactory.getLogger(WsseService::class.java)
    }
}
