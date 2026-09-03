package kz.ncanode.service

import kz.ncanode.dto.request.XmlSignBatchRequest
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.request.XmlVerifyBatchRequest
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.dto.response.XmlSignBatchResponse
import kz.ncanode.dto.response.XmlSignResponse
import kz.ncanode.dto.response.XmlVerifyBatchResponse
import kz.ncanode.exception.ClientException
import kz.ncanode.util.mapPartial
import kz.ncanode.util.warnIfRevocationDisabled
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.apache.xml.security.utils.Constants
import org.slf4j.LoggerFactory
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
            val signatures = document.documentElement.getElementsByTagName("ds:Signature")
            // Снимок узлов ДО удаления: getElementsByTagName отдаёт live NodeList,
            // который переиндексируется при removeChild. Итерация `0 until length`
            // фиксирует границу один раз, список укорачивается → на ≥2 подписях
            // item(i) становится null → падение (+ удаление не тех узлов). Удаляем
            // через parentNode, а не root — подпись может быть не прямым потомком.
            val toRemove = (0 until signatures.length).mapNotNull { signatures.item(it) }
            toRemove.forEach { it.parentNode?.removeChild(it) }
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
        val items = request.xmls.mapPartial({ status, message ->
            XmlSignBatchResponse.Item(status = status, message = message)
        }) { xml ->
            val itemRequest = XmlSignRequest().apply {
                this.xml = xml
                this.signers = request.signers
                this.isClearSignatures = request.isClearSignatures
                this.isTrimXml = request.isTrimXml
            }
            XmlSignBatchResponse.Item(xml = sign(itemRequest).xml)
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
        val checkOcsp = request.checkOcsp
        val checkCrl = request.checkCrl
        val items = request.xmls.mapPartial({ status, message ->
            VerificationResponse(valid = false, status = status, message = message)
        }) { xml ->
            verify(xml, checkOcsp, checkCrl)
        }
        return XmlVerifyBatchResponse(results = items)
    }

    /**
     * Проверяет XML-подписи.
     */
    fun verify(
        xml: String,
        checkOcsp: Boolean,
        checkCrl: Boolean,
        /**
         * Вызывается для каждой подписи до её проверки: получает сертификат и
         * сам элемент `ds:Signature`. Позволяет заранее прикрепить вердикты по
         * вшитому материалу (уровень LT) — тогда `attachValidationData` за ними
         * в сеть не пойдёт. По умолчанию ничего не делает, поведение прежних
         * вызовов не меняется.
         */
        prepare: (CertificateWrapper, Element) -> Unit = { _, _ -> },
        /**
         * Вызывается после проверки каждой подписи: элемент и её собственный
         * вердикт. Общий флаг по документу не даёт понять, какая из подписей
         * не прошла, а AdES-слой сообщает это по каждой отдельно.
         */
        onSignature: (Element, Boolean) -> Unit = { _, _ -> },
    ): VerificationResponse {
        warnIfRevocationDisabled(checkOcsp, checkCrl)
        val document = read(xml, false)
        val root = document.documentElement

        // Подпись может быть и самим корнем — тогда документ лежит внутри неё
        // (ENVELOPING). `getElementsByTagName` ищет только потомков, поэтому
        // такой документ выглядел как «подписей нет» и отвергался.
        val rootIsSignature = root.namespaceURI == Constants.SignatureSpecNS && root.localName == "Signature"
        val initial = if (rootIsSignature) 1 else root.getElementsByTagName("ds:Signature").length

        var valid = initial > 0
        val certs = mutableListOf<CertificateWrapper?>()
        val currentDate = certificateService.getCurrentDate()

        // NodeList "живой": removeChild уменьшает длину, поэтому всегда берём
        // последний элемент. Так каждый ds:Signature обрабатывается ровно раз.
        while (if (rootIsSignature) certs.isEmpty() else root.getElementsByTagName("ds:Signature").length > 0) {
            val signature = if (rootIsSignature) {
                root
            } else {
                val live = root.getElementsByTagName("ds:Signature")
                live.item(live.length - 1) as? Element
                    ?: throw ClientException("Bad signature: Element 'ds:Reference' is not found in XML document")
            }

            val xmlSignature = XMLSignatureWrapper(signature)
            val cert = xmlSignature.certificate

            if (cert == null) {
                valid = false
                onSignature(signature, false)
                certs.add(null)
                signature.parentNode?.removeChild(signature)
                continue
            }

            prepare(cert, signature)
            certificateService.attachValidationData(cert, checkOcsp, checkCrl)

            // check() подтверждает только целостность дайджестов Reference'ов.
            // Дополнительно требуем, чтобы подпись покрывала ВЕСЬ документ
            // (whole-document enveloped Reference) — иначе blanket valid=true над
            // присланным XML вводит в заблуждение (XML Signature Wrapping).
            val coversWhole = xmlSignature.coversWholeDocument()
            if (!coversWhole) {
                log.warn("XML signature does not cover the whole document — rejecting (possible XML Signature Wrapping)")
            }
            val signatureValid = xmlSignature.check() &&
                coversWhole &&
                cert.isValid(currentDate, checkOcsp, checkCrl)
            if (!signatureValid) {
                valid = false
            }
            onSignature(signature, signatureValid)
            // Удаляем через parentNode: подпись может быть вложена не в корень
            // (enveloped внутри контейнера) — root.removeChild тогда бросал
            // DOMException → 500 вместо честного valid=false.
            signature.parentNode?.removeChild(signature)

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

    companion object {
        private val log = LoggerFactory.getLogger(XmlService::class.java)
    }
}
