package kz.ncanode.service

import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.request.XmlSignBatchRequest
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.request.XmlVerifyBatchRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignBatchResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.dto.response.XmlVerifyBatchResponse
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import org.springframework.http.HttpStatus
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.springframework.stereotype.Service
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import org.w3c.dom.traversal.DocumentTraversal
import org.w3c.dom.traversal.NodeFilter

/**
 * XML/XMLDSIG Service.
 *
 * Сервис отвечает за всё что связано с XML/XMLDSIG.
 */
@Service
class XmlService(
    private val kalkanWrapper: KalkanWrapper,
    private val certificateService: CertificateService,
) {

    /**
     * Read XML from String.
     */
    fun read(xml: String, removeSignatures: Boolean): DocumentWrapper {
        val document = DocumentWrapper(xml)

        if (removeSignatures) {
            val root = document.documentElement
            val signatures = root.getElementsByTagName("ds:Signature")
            for (i in 0 until signatures.length) {
                root.removeChild(signatures.item(i))
            }
        }

        return document
    }

    /**
     * Batch-подпись: каждый XML в [XmlSignBatchRequest.xmls] подписывается
     * общим набором signer'ов. Partial response — ошибка на N-м item'е
     * не валит остальные. Результирующий `status` каждого item'а:
     *  - 200 если успех,
     *  - status из [ApplicationException] (e.g. 400 для ClientException),
     *  - 500 для прочих исключений.
     *
     * Sequential обработка осознанная: KalkanProvider thread-safety на
     * GOST 2015 не доверяем без полного аудита; CPU-bound parallelism —
     * возможная оптимизация после нагрузочных тестов.
     */
    fun signBatch(request: XmlSignBatchRequest): XmlSignBatchResponse {
        val items = request.xmls.map { xml ->
            try {
                val itemRequest = XmlSignRequest().apply {
                    this.xml = xml
                    this.signers = request.signers
                    this.isClearSignatures = request.isClearSignatures
                    this.isTrimXml = request.isTrimXml
                }
                val response = sign(itemRequest)
                XmlSignBatchResponse.Item(xml = response.xml)
            } catch (e: ApplicationException) {
                XmlSignBatchResponse.Item(status = e.status, message = e.message)
            } catch (e: Exception) {
                XmlSignBatchResponse.Item(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    message = e.message,
                )
            }
        }
        return XmlSignBatchResponse(results = items)
    }

    /**
     * Подписывает XML.
     */
    fun sign(xmlSignRequest: XmlSignRequest): XmlSignResponse {
        val document = read(xmlSignRequest.xml, xmlSignRequest.isClearSignatures)

        if (xmlSignRequest.isTrimXml) {
            removeWhitespace(document.document)
        }

        val signers = xmlSignRequest.signers
        kalkanWrapper.read(signers).forEachIndexed { i, keyStore ->
            document.createXmlSignature(keyStore.certificate, signers[i].referenceUri)
                .sign(keyStore.privateKey)
        }

        return XmlSignResponse(xml = document.toString())
    }

    /**
     * Batch-верификация: каждый XML в [XmlVerifyBatchRequest.xmls] проверяется
     * с общими revocation-флагами. На ошибку парсинга/верификации — item
     * получает `valid=false` + status/message; остальные продолжают.
     *
     * Aggregate-флаг valid намеренно НЕ публикуется на top-level — это
     * сразу прячет ошибки в одном из item'ов, что для mass-flow вреднее
     * partial-response'а.
     */
    fun verifyBatch(request: XmlVerifyBatchRequest): XmlVerifyBatchResponse {
        val checkOcsp = CertificateRevocation.OCSP in request.revocationCheck
        val checkCrl = CertificateRevocation.CRL in request.revocationCheck
        val items = request.xmls.map { xml ->
            try {
                verify(xml, checkOcsp, checkCrl)
            } catch (e: ApplicationException) {
                VerificationResponse(valid = false, status = e.status, message = e.message)
            } catch (e: Exception) {
                VerificationResponse(
                    valid = false,
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    message = e.message,
                )
            }
        }
        return XmlVerifyBatchResponse(results = items)
    }

    /**
     * Проверяет XML-подписи.
     */
    fun verify(xml: String, checkOcsp: Boolean, checkCrl: Boolean): VerificationResponse {
        val document = read(xml, false)
        val root = document.documentElement
        val initial = root.getElementsByTagName("ds:Signature").length

        var valid = initial > 0
        val certs = mutableListOf<CertificateWrapper?>()
        val currentDate = certificateService.getCurrentDate()

        // NodeList "живой": removeChild уменьшает длину, поэтому всегда берём
        // последний элемент. Так каждый ds:Signature обрабатывается ровно раз.
        while (root.getElementsByTagName("ds:Signature").length > 0) {
            val live = root.getElementsByTagName("ds:Signature")
            val signature = live.item(live.length - 1) as? Element
                ?: throw ClientException("Bad signature: Element 'ds:Reference' is not found in XML document")

            val xmlSignature = XMLSignatureWrapper(signature)
            val cert = xmlSignature.certificate

            if (cert == null) {
                valid = false
                certs.add(null)
                root.removeChild(signature)
                continue
            }

            certificateService.attachValidationData(cert, checkOcsp, checkCrl)

            if (!xmlSignature.check() || !cert.isValid(currentDate, checkOcsp, checkCrl)) {
                valid = false
            }
            root.removeChild(signature)

            certs.add(cert)
        }

        return VerificationResponse(
            valid = valid,
            signers = certs.map { it?.toCertificateInfo(currentDate, checkOcsp, checkCrl) },
        )
    }

    fun prepare(xml: String, trimXml: Boolean): String =
        (if (trimXml) removeWhitespace(xml) else xml).trim()

    fun removeWhitespace(document: Document) {
        val toRemove = mutableSetOf<Node>()
        val traversal = document as DocumentTraversal
        val it = traversal.createNodeIterator(document, NodeFilter.SHOW_TEXT, null, true)

        var n = it.nextNode()
        while (n != null) {
            if (n.nodeValue.trim().isEmpty()) {
                toRemove.add(n)
            }
            n = it.nextNode()
        }

        for (node in toRemove) {
            node.parentNode.removeChild(node)
        }
    }

    fun removeWhitespace(xml: String): String {
        val document = read(xml, false)
        removeWhitespace(document.document)
        return document.toString()
    }
}
