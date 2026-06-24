package kz.ncanode.wrapper

import kz.ncanode.exception.ServerException
import org.apache.xml.security.exceptions.XMLSecurityException
import org.apache.xml.security.keys.keyresolver.KeyResolverException
import org.apache.xml.security.signature.Reference
import org.apache.xml.security.signature.XMLSignature
import org.apache.xml.security.signature.XMLSignatureException
import org.apache.xml.security.transforms.Transforms
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
            transforms.item(i).uri in ALLOWED_WHOLE_DOC_TRANSFORMS
        }
    } catch (e: XMLSecurityException) {
        false
    }

    companion object {
        private val log = LoggerFactory.getLogger(XMLSignatureWrapper::class.java)

        /**
         * Трансформы, не сужающие покрытие Reference'а: enveloped-signature
         * (вырезает саму подпись) + варианты canonicalization. Всё остальное
         * (XPath, XSLT, base64, …) потенциально меняет node-set и не считается
         * покрывающим весь документ.
         */
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
