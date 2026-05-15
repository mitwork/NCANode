package kz.ncanode.wrapper

import kz.ncanode.exception.ServerException
import org.apache.xml.security.encryption.XMLCipherParameters
import org.apache.xml.security.exceptions.XMLSecurityException
import org.apache.xml.security.transforms.Transforms
import org.slf4j.LoggerFactory
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.xml.sax.SAXException
import java.io.IOException
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.ParserConfigurationException
import javax.xml.transform.TransformerException
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

class DocumentWrapper(val document: Document) {

    constructor(xmlStr: String) : this(parse(xmlStr))

    val documentElement: Element
        get() = document.documentElement

    /**
     * Создает и добавляет XMLDSIG подпись.
     */
    fun createXmlSignature(certificateWrapper: CertificateWrapper, referenceUri: String?): XMLSignatureWrapper {
        val sig = XMLSignatureWrapper(document, certificateWrapper.signAlgorithmId)
        document.documentElement.appendChild(sig.xmlSignature.element)
        val transforms = Transforms(document)

        try {
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)
            transforms.addTransform(XMLCipherParameters.N14C_XML_CMMNTS)
            sig.xmlSignature.addDocument(referenceUri ?: "", transforms, certificateWrapper.hashAlgorithmId)
            sig.xmlSignature.addKeyInfo(certificateWrapper.x509Certificate)
        } catch (e: XMLSecurityException) {
            log.error("XMLDSig Signature creation error", e)
            throw ServerException("XMLDSig Signature creation error", e)
        }

        return sig
    }

    override fun toString(): String = try {
        StringWriter().use { stringWriter ->
            val tf = TransformerFactory.newInstance()
            // Hardening: блокирует доступ к внешним сущностям/DTD при
            // сериализации, даже если бы они проникли в DOM.
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
            val transformer = tf.newTransformer()
            transformer.transform(DOMSource(document), StreamResult(stringWriter))
            stringWriter.toString()
        }
    } catch (e: IOException) {
        log.error("XML generation error", e)
        throw ServerException("XML generation error", e)
    } catch (e: TransformerException) {
        log.error("XML generation error", e)
        throw ServerException("XML generation error", e)
    }

    companion object {
        private val log = LoggerFactory.getLogger(DocumentWrapper::class.java)

        private fun parse(xmlStr: String): Document {
            try {
                val factory = DocumentBuilderFactory.newInstance().apply {
                    isNamespaceAware = true
                    isXIncludeAware = false
                    isExpandEntityReferences = false
                    setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
                }

                // OWASP рекомендует "disallow-doctype-decl=true" как первичную
                // защиту от XXE, но это ломает легитимный XMLDSIG-кейс с
                // внутренним DTD для объявления ID-атрибутов
                // (<!ATTLIST x id ID>). Поэтому DOCTYPE разрешаем, но
                // обезвреживаем все векторы: external entities, external
                // parameter entities, external DTD — запрещены ниже. Плюс
                // FEATURE_SECURE_PROCESSING (выше) ограничивает
                // entity-expansion (billion-laughs).
                val featuresToDisable = listOf(
                    "http://xml.org/sax/features/external-general-entities",
                    "http://xml.org/sax/features/external-parameter-entities",
                    "http://apache.org/xml/features/nonvalidating/load-external-dtd",
                )
                for (feature in featuresToDisable) {
                    try {
                        factory.setFeature(feature, false)
                    } catch (e: ParserConfigurationException) {
                        log.error("ParserConfigurationException was thrown. The feature $feature is probably not supported by your XML processor.")
                    }
                }

                val builder = factory.newDocumentBuilder()
                xmlStr.trim().byteInputStream(StandardCharsets.UTF_8).use { stream ->
                    return builder.parse(stream) ?: throw ServerException("Cannot read XML")
                }
            } catch (e: ParserConfigurationException) {
                log.error("XML parsing error", e)
                throw ServerException("Cannot read XML", e)
            } catch (e: IOException) {
                log.error("XML parsing error", e)
                throw ServerException("Cannot read XML", e)
            } catch (e: SAXException) {
                log.error("XML parsing error", e)
                throw ServerException("Cannot read XML", e)
            }
        }
    }
}
