package kz.ncanode.wrapper

import kz.ncanode.exception.ServerException
import org.apache.xml.security.exceptions.XMLSecurityException
import org.apache.xml.security.keys.keyresolver.KeyResolverException
import org.apache.xml.security.signature.Reference
import org.apache.xml.security.signature.XMLSignature
import org.apache.xml.security.signature.XMLSignatureException
import org.apache.xml.security.utils.Constants
import org.apache.xml.security.transforms.Transform
import org.apache.xml.security.transforms.Transforms
import org.apache.xml.security.utils.XMLUtils
import org.slf4j.LoggerFactory
import org.w3c.dom.DOMException
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.security.PrivateKey

class XMLSignatureWrapper {

    val xmlSignature: XMLSignature

    constructor(signature: Element) {
        xmlSignature = try {
            XMLSignature(signature, "")
        } catch (e: XMLSecurityException) {
            throw ServerException("XML Signature creation error", e)
        }
        registerXadesIds(signature)
    }

    /**
     * Помечает `Id`-атрибуты XAdES-свойств как настоящие ID.
     *
     * XAdES-подпись содержит вторую Reference на `xades:SignedProperties` по
     * `URI="#..."`. При разборе чужого XML парсер не знает схемы, поэтому
     * `getElementById` такой элемент не находит, ссылка не резолвится и
     * проверка подписи падает — то есть любая XAdES-подпись (в том числе всё,
     * что выпускает NCALayer) считалась бы невалидной.
     *
     * Делается в конструкторе намеренно: обёртка над уже готовой подписью
     * создаётся только чтобы её проверить, а забытый вызов давал бы не ошибку,
     * а тихий неверный вердикт. Область ограничена поддеревом самой подписи —
     * чужие элементы документа не затрагиваются.
     */
    private fun registerXadesIds(signature: Element) {
        for (namespace in XADES_NAMESPACES) {
            val nodes = signature.getElementsByTagNameNS(namespace, "*")
            for (i in 0 until nodes.length) {
                val element = nodes.item(i) as? Element ?: continue
                if (element.getAttribute("Id").isEmpty()) continue
                try {
                    element.setIdAttribute("Id", true)
                } catch (e: DOMException) {
                    log.debug("Cannot mark {} Id as an ID attribute: {}", element.nodeName, e.message)
                }
            }
        }
    }

    constructor(document: Document, signAlgorithmId: String) {
        xmlSignature = try {
            XMLSignature(document, "", signAlgorithmId)
        } catch (e: XMLSecurityException) {
            throw ServerException("XML Signature creation error", e)
        }
    }

    constructor(document: Document, signAlgorithmId: String, c14nAlgorithmId: String) {
        xmlSignature = try {
            val signatureMethod = XMLUtils.createElementInSignatureSpace(document, "SignatureMethod")
            signatureMethod.setAttributeNS(null, "Algorithm", signAlgorithmId)

            val c14nMethod = XMLUtils.createElementInSignatureSpace(document, "CanonicalizationMethod")
            c14nMethod.setAttributeNS(null, "Algorithm", c14nAlgorithmId)

            XMLSignature(document, "", signatureMethod, c14nMethod)
        } catch (e: XMLSecurityException) {
            log.error("XML Signature creation error", e)
            throw ServerException("XML Signature creation error", e)
        }
    }

    fun sign(privateKey: PrivateKey) {
        try {
            xmlSignature.sign(privateKey)
        } catch (e: XMLSignatureException) {
            log.error("XML Signing error", e)
            throw ServerException("XML Signing error", e)
        }
    }

    val certificate: CertificateWrapper?
        get() = try {
            CertificateWrapper(xmlSignature.keyInfo.x509Certificate)
        } catch (e: KeyResolverException) {
            null
        }

    fun check(): Boolean = try {
        val cert = certificate ?: return false
        xmlSignature.checkSignatureValue(cert.x509Certificate)
    } catch (e: XMLSignatureException) {
        false
    }

    /**
     * Покрывает ли подпись весь документ (защита от XML Signature Wrapping).
     *
     * `check()` (Santuario `checkSignatureValue`) подтверждает лишь, что
     * дайджесты Reference'ов совпадают с тем, на что они ссылаются — но НЕ что
     * подписан именно тот контент, который потребитель считает подписанным.
     * Атакующий может прислать подпись с `URI="#id"` на безобидный под-элемент
     * (или его обёрнутую копию), оставив реальную нагрузку неподписанной, и
     * получить blanket `valid=true`.
     *
     * Считаем подпись покрывающей весь документ, если есть хотя бы один
     * Reference с пустым URI (whole-document, enveloped — ровно то, что строит
     * наш [DocumentWrapper.createXmlSignature]) и только безопасными
     * трансформами (enveloped-signature + canonicalization). Трансформы вроде
     * XPath/XSLT могут сузить покрытие до под-узла даже при `URI=""`, поэтому
     * любой трансформ вне белого списка дисквалифицирует Reference.
     */
    fun coversWholeDocument(): Boolean = try {
        val signedInfo = xmlSignature.signedInfo
        (0 until signedInfo.length).any { i ->
            val ref = signedInfo.item(i)
            ref.uri.isNullOrEmpty() && transformsWholeDocumentSafe(ref)
        }
    } catch (e: XMLSecurityException) {
        log.warn("Failed to inspect XML signature references for whole-document coverage", e)
        false
    }

    private fun transformsWholeDocumentSafe(reference: Reference): Boolean = try {
        val transforms = reference.transforms ?: return true
        (0 until transforms.length).all { i ->
            val transform = transforms.item(i)
            transform.uri in ALLOWED_WHOLE_DOC_TRANSFORMS || excludesAllSignatures(transform)
        }
    } catch (e: XMLSecurityException) {
        false
    }

    /**
     * XPath, вырезающий из покрытия **все** подписи, а не только свою.
     *
     * Это единственное исключение из запрета на XPath: произвольное выражение
     * сужает node-set непредсказуемо (XML Signature Wrapping), поэтому
     * сравниваем текст выражения дословно. Смысл у него ровно тот же, что у
     * enveloped-signature, но действует на все подписи сразу — так документ с
     * несколькими подписями остаётся проверяемым для тех, кто не умеет
     * снимать более поздние подписи.
     */
    private fun excludesAllSignatures(transform: Transform): Boolean {
        if (transform.uri != Transforms.TRANSFORM_XPATH) return false
        val expression = transform.element
            .getElementsByTagNameNS(Constants.SignatureSpecNS, "XPath")
            .item(0)
            ?.textContent
            ?.replace(Regex("\\s+"), " ")
            ?.trim()
        return expression == EXCLUDE_ALL_SIGNATURES_XPATH
    }

    companion object {
        private val log = LoggerFactory.getLogger(XMLSignatureWrapper::class.java)

        /** Пространства имён XAdES, в которых встречаются Id-несущие свойства. */
        private val XADES_NAMESPACES = listOf(
            "http://uri.etsi.org/01903/v1.3.2#",
            "http://uri.etsi.org/01903/v1.4.1#",
            "http://uri.etsi.org/01903/v1.1.1#",
        )

        /**
         * Трансформы, не сужающие покрытие Reference'а: enveloped-signature
         * (вырезает саму подпись) + варианты canonicalization. Всё остальное
         * (XPath, XSLT, base64, …) потенциально меняет node-set и не считается
         * покрывающим весь документ.
         */
        /** Выражение, исключающее из покрытия все `ds:Signature`. */
        const val EXCLUDE_ALL_SIGNATURES_XPATH = "not(ancestor-or-self::ds:Signature)"

        private val ALLOWED_WHOLE_DOC_TRANSFORMS = setOf(
            Transforms.TRANSFORM_ENVELOPED_SIGNATURE,
            Transforms.TRANSFORM_C14N_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N11_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N11_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS,
        )
    }
}
