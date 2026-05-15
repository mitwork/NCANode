package kz.ncanode.wrapper

import kz.ncanode.exception.ServerException
import org.apache.xml.security.exceptions.XMLSecurityException
import org.apache.xml.security.keys.keyresolver.KeyResolverException
import org.apache.xml.security.signature.XMLSignature
import org.apache.xml.security.signature.XMLSignatureException
import org.apache.xml.security.utils.XMLUtils
import org.slf4j.LoggerFactory
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

    companion object {
        private val log = LoggerFactory.getLogger(XMLSignatureWrapper::class.java)
    }
}
