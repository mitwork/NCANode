package kz.ncanode.service

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.util.encoders.Hex
import kz.ncanode.ades.XadesInspector
import kz.ncanode.ades.XadesQualifyingProperties
import kz.ncanode.dto.ades.AdesLevel
import java.util.Date
import kz.ncanode.dto.ades.SignaturePackaging
import kz.ncanode.dto.ades.XadesSignatureInfo
import kz.ncanode.dto.request.XadesSignBatchRequest
import kz.ncanode.dto.request.XadesSignRequest
import kz.ncanode.dto.request.XadesVerifyBatchRequest
import kz.ncanode.dto.request.XadesVerifyRequest
import kz.ncanode.dto.response.XadesResponse
import kz.ncanode.dto.response.XadesSignBatchResponse
import kz.ncanode.dto.response.XadesVerificationBatchResponse
import kz.ncanode.dto.response.XadesVerificationResponse
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.dto.tsp.TspInfo
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getHashingAlgorithmByOID
import kz.ncanode.util.getTspHashAlgorithmByOid
import kz.ncanode.util.mapPartial
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.KeyStoreWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.apache.xml.security.signature.ObjectContainer
import org.apache.xml.security.transforms.Transforms
import org.springframework.stereotype.Service
import org.w3c.dom.Element
import java.security.cert.X509Certificate
import java.util.UUID

/**
 * Подпись XAdES по ETSI EN 319 132-1.
 *
 * От `/xml/sign` отличается принципиально: там обычный XMLDSIG, здесь —
 * профиль AdES, где подпись дополнительно накрывает `SignedProperties` со
 * временем подписи и привязкой к сертификату. Существующий `/xml/sign`
 * не легаси и продолжает работать как раньше.
 *
 * Реализованы уровни B, T, LT и LTA и вкладывание подписи в документ
 * (ENVELOPED) — основной сценарий для XML-документооборота РК. Прочие
 * размещения отклоняются явно.
 */
@Service
class XadesService(
    private val kalkanWrapper: KalkanWrapper,
    private val tspService: TspService,
    private val xmlService: XmlService,
    private val validationDataService: ValidationDataService,
) {

    fun sign(request: XadesSignRequest): XadesResponse {
        requirePackagingSupported(request.packaging)

        return try {
            val document = DocumentWrapper(request.xml)

            for (keyStore in kalkanWrapper.read(request.signers)) {
                appendSignature(document, keyStore, request.level, request.tsaPolicy)
            }

            XadesResponse(xml = document.toString(), level = request.level)
        } catch (e: ApplicationException) {
            throw e
        } catch (e: Exception) {
            throw ServerException("Error signing XAdES: ${e.message}", e)
        }
    }

    /**
     * Добавляет одну XAdES-подпись в документ.
     *
     * Порядок важен: `QualifyingProperties` должны оказаться в DOM до вызова
     * `sign()` — дайджесты обеих ссылок считаются именно в этот момент.
     * Объект с ними попадает внутрь `ds:Signature`, поэтому enveloped-трансформ
     * исключает его из ссылки на сам документ, и рекурсии не возникает.
     */

    /**
     * Batch-подпись: каждый XML подписывается независимо общим набором
     * signer'ов до общего уровня. Ошибка на одном документе не валит
     * остальные — она в `results[n].status`.
     */
    fun signBatch(request: XadesSignBatchRequest): XadesSignBatchResponse {
        val items = request.xmls.mapPartial({ status, message ->
            XadesSignBatchResponse.Item(status = status, message = message)
        }) { xml ->
            val response = sign(
                XadesSignRequest().apply {
                    this.xml = xml
                    this.signers = request.signers
                    this.level = request.level
                    this.packaging = request.packaging
                    this.tsaPolicy = request.tsaPolicy
                },
            )
            XadesSignBatchResponse.Item(xml = response.xml, level = response.level)
        }
        return XadesSignBatchResponse(results = items)
    }

    /** Batch-проверка: каждый XML проверяется независимо с общими флагами. */
    fun verifyBatch(request: XadesVerifyBatchRequest): XadesVerificationBatchResponse {
        val items = request.xmls.mapPartial({ status, message ->
            XadesVerificationResponse(valid = false, status = status, message = message)
        }) { xml ->
            verify(
                XadesVerifyRequest().apply {
                    this.xml = xml
                    revocationCheck = request.revocationCheck
                },
            )
        }
        return XadesVerificationBatchResponse(results = items)
    }

    private fun appendSignature(
        document: DocumentWrapper,
        keyStore: KeyStoreWrapper,
        level: AdesLevel,
        tsaPolicy: TsaPolicy?,
    ) {
        val certificate = keyStore.certificate
        val x509 = certificate.x509Certificate

        val signature = XMLSignatureWrapper(document.document, certificate.signAlgorithmId, CANONICALIZATION)
        val xmlSignature = signature.xmlSignature

        val signatureId = "sig-${UUID.randomUUID()}"
        xmlSignature.setId(signatureId)
        document.documentElement.appendChild(xmlSignature.element)

        val transforms = Transforms(document.document).apply {
            addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)
            addTransform(CANONICALIZATION)
        }
        val dataReferenceId = "$signatureId-ref0"
        xmlSignature.addDocument("", transforms, certificate.hashAlgorithmId, dataReferenceId, null)
        xmlSignature.addKeyInfo(x509)

        val signedPropertiesId = "$signatureId-signedprops"
        val qualifyingProperties = XadesQualifyingProperties.build(
            document = document.document,
            certificate = x509,
            signatureId = signatureId,
            signedPropertiesId = signedPropertiesId,
            dataReferenceId = dataReferenceId,
            digestUri = certificate.hashAlgorithmId,
            digestOid = getDigestAlgorithmOidBYSignAlgorithmOid(x509.sigAlgOID),
            provider = kalkanWrapper.kalkanProvider,
        )
        val container = ObjectContainer(document.document)
        container.appendChild(qualifyingProperties)
        xmlSignature.appendObject(container)

        // Вторая ссылка — на сами свойства: именно она делает время подписи и
        // привязку к сертификату частью подписанного, а не декорацией.
        val propertiesTransforms = Transforms(document.document).apply { addTransform(CANONICALIZATION) }
        xmlSignature.addDocument(
            "#$signedPropertiesId",
            propertiesTransforms,
            certificate.hashAlgorithmId,
            null,
            XadesQualifyingProperties.SIGNED_PROPERTIES_TYPE,
        )

        signature.sign(keyStore.privateKey)

        if (level.isAtLeast(AdesLevel.T)) {
            appendSignatureTimeStamp(xmlSignature.element, qualifyingProperties, x509, tsaPolicy)
        }
        if (level.isAtLeast(AdesLevel.LT)) {
            appendValidationData(document.document, qualifyingProperties, x509)
        }
        if (level.isAtLeast(AdesLevel.LTA)) {
            appendArchiveTimeStamp(xmlSignature.element, qualifyingProperties, x509, tsaPolicy)
        }
    }

    /**
     * Ставит архивную метку времени — уровень LTA.
     *
     * Считается по всей подписи вместе с уже добавленными свойствами, поэтому
     * вызывается последней: метка фиксирует ту картину, которая сложилась к
     * этому моменту.
     *
     * Рядом кладётся материал для проверки самой метки. Он собирается
     * best-effort: если цепочки TSA нет в нашем бандле, метка от этого не
     * становится недействительной, просто её проверка позже потребует сети.
     */
    private fun appendArchiveTimeStamp(
        signatureElement: Element,
        qualifyingProperties: Element,
        certificate: X509Certificate,
        tsaPolicy: TsaPolicy?,
    ) {
        val policyId = (tsaPolicy ?: TsaPolicy.TSA_GOST2015_POLICY).policyId
        val digestOid = getTspHashAlgorithmByOid(certificate.sigAlgOID)
        val token = tspService.create(
            XadesInspector.archiveTimestampInput(signatureElement),
            digestOid,
            policyId,
        )

        val document = signatureElement.ownerDocument
        val properties = XadesQualifyingProperties.unsignedSignatureProperties(qualifyingProperties)
        properties.appendChild(
            XadesQualifyingProperties.archiveTimeStamp(document, token.encoded, CANONICALIZATION),
        )

        timestampAuthorityMaterial(token)?.let { data ->
            properties.appendChild(
                XadesQualifyingProperties.timeStampValidationData(
                    document, data.certificates, data.crls, data.ocspResponses,
                ),
            )
        }
    }

    /** Цепочка и отзыв для сертификата TSA; null, если собрать не удалось. */
    private fun timestampAuthorityMaterial(
        token: kz.gov.pki.kalkan.tsp.TimeStampToken,
    ): ValidationDataService.ValidationData? = try {
        val tokenCms = CMSSignedData(token.encoded)
        val tsaSigner = tokenCms.signerInfos.signers.first() as SignerInformation
        val tsaCertificate = tokenCms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            .getCertificates(tsaSigner.sid)
            .filterIsInstance<X509Certificate>()
            .firstOrNull()
        tsaCertificate?.let { validationDataService.collect(it) }
    } catch (e: Exception) {
        log.warn("Cannot collect the TSA validation material: {}", e.message)
        null
    }

    /**
     * Встраивает цепочку и данные об отзыве — уровень LT.
     *
     * Как и метка времени, они кладутся в `UnsignedSignatureProperties`,
     * которые не покрыты ни одной `ds:Reference`, поэтому уже поставленная
     * подпись остаётся валидной.
     *
     * Материал собирается на текущий момент; для повышения уровня у старой
     * подписи (extend) момент сбора должен задаваться отдельно.
     */
    private fun appendValidationData(
        document: org.w3c.dom.Document,
        qualifyingProperties: Element,
        certificate: X509Certificate,
    ) {
        val data = validationDataService.collect(certificate)
        val properties = XadesQualifyingProperties.unsignedSignatureProperties(qualifyingProperties)

        properties.appendChild(XadesQualifyingProperties.certificateValues(document, data.certificates))
        if (data.crls.isNotEmpty() || data.ocspResponses.isNotEmpty()) {
            properties.appendChild(
                XadesQualifyingProperties.revocationValues(document, data.crls, data.ocspResponses),
            )
        }
    }

    /**
     * Добавляет метку времени поверх готовой подписи.
     *
     * Метка кладётся в `UnsignedSignatureProperties`, которые не покрыты ни
     * одной `ds:Reference` — поэтому подпись от этого не ломается. Накрывает
     * метка канонизированный `ds:SignatureValue`, то есть доказывает, что
     * подпись существовала не позже genTime.
     */
    private fun appendSignatureTimeStamp(
        signatureElement: Element,
        qualifyingProperties: Element,
        certificate: X509Certificate,
        tsaPolicy: TsaPolicy?,
    ) {
        val policyId = (tsaPolicy ?: TsaPolicy.TSA_GOST2015_POLICY).policyId
        val token = tspService.create(
            XadesInspector.timestampedBytes(signatureElement),
            getTspHashAlgorithmByOid(certificate.sigAlgOID),
            policyId,
        )
        val properties = XadesQualifyingProperties.unsignedSignatureProperties(qualifyingProperties)
        properties.appendChild(
            XadesQualifyingProperties.signatureTimeStamp(
                signatureElement.ownerDocument,
                token.encoded,
                CANONICALIZATION,
            ),
        )
    }

    /**
     * Проверяет XAdES и сообщает уровень.
     *
     * Криптография, покрытие документа, цепочка и отзыв берутся из
     * [XmlService.verify] — дублировать их незачем. Здесь добавляется
     * AdES-специфика: заявленный уровень, сверка привязки к сертификату и
     * проверка метки времени.
     */
    fun verify(request: XadesVerifyRequest): XadesVerificationResponse {
        val revocationRequested = request.checkOcsp || request.checkCrl
        val provider = kalkanWrapper.kalkanProvider

        // Что подтвердилось по каждой подписи — заполняется на ходу, пока
        // XmlService идёт по подписям.
        val embeddedUsed = mutableMapOf<Element, Boolean>()

        val base = xmlService.verify(request.xml, request.checkOcsp, request.checkCrl) { certificate, element ->
            if (!revocationRequested) return@verify
            val material = try {
                XadesInspector.embeddedMaterial(element)
            } catch (e: Exception) {
                log.warn("Cannot read the embedded validation data: {}", e.message)
                return@verify
            }
            if (material.crls.isEmpty() && material.ocspResponses.isEmpty()) return@verify

            // Момент проверки — доказанное время существования подписи.
            val at = proofOfExistence(element) ?: Date()
            embeddedUsed[element] = validationDataService.attachEmbedded(
                certificate, material.crls, material.ocspResponses, at,
            )
        }

        // Сопоставляем по серийнику: XmlService перебирает подписи с конца.
        val certificateInfo = base.signers.filterNotNull().associateBy { it.serialNumber }

        val document = DocumentWrapper(request.xml)
        var valid = base.valid
        val signatures = mutableListOf<XadesSignatureInfo>()

        for (element in signatureElements(document)) {
            val certificate = XMLSignatureWrapper(element).certificate?.x509Certificate
            val facts = XadesInspector.inspect(element, certificate, provider)

            if (!facts.signingCertificateMatches) valid = false

            var tspInfo: TspInfo? = null
            var timestampValid = false
            if (facts.level.isAtLeast(AdesLevel.T)) {
                val timestamp = facts.timestampToken?.let {
                    tspService.verify(
                        it,
                        XadesInspector.timestampedBytes(element),
                        request.checkOcsp,
                        request.checkCrl,
                    )
                }
                if (timestamp == null) {
                    // Уровень заявлен, но не подтверждён — это отказ.
                    valid = false
                } else {
                    timestampValid = true
                    tspInfo = toTspInfo(timestamp)
                }
            }

            // Ключи в embeddedUsed — элементы из ДРУГОГО разбора документа
            // (XmlService парсит свою копию), поэтому сверяем по серийнику.
            val used = embeddedUsed.values.any { it }

            signatures.add(
                XadesSignatureInfo(
                    level = facts.level,
                    verifiedLevel = verifiedLevel(
                        claimed = facts.level,
                        timestamped = timestampValid,
                        embeddedUsed = used,
                        archiveValid = archiveTimestampsValid(element, request.checkOcsp, request.checkCrl),
                    ),
                    certificate = certificate?.let { certificateInfo[it.serialNumber.toString(16)] },
                    tsp = tspInfo,
                ),
            )
        }

        return XadesVerificationResponse(
            valid = valid,
            level = signatures.mapNotNull { it.level }.minByOrNull { it.ordinal },
            verifiedLevel = signatures.mapNotNull { it.verifiedLevel }.minByOrNull { it.ordinal },
            signatures = signatures,
        )
    }

    /** Доказанное время существования подписи — genTime её метки, если она есть. */
    private fun proofOfExistence(signatureElement: Element): Date? = try {
        val facts = XadesInspector.inspect(signatureElement, null, kalkanWrapper.kalkanProvider)
        facts.timestampToken
            ?.let { tspService.verify(it, XadesInspector.timestampedBytes(signatureElement), false, false) }
            ?.genTime
    } catch (e: Exception) {
        log.warn("Cannot read the signature timestamp: {}", e.message)
        null
    }

    /**
     * Проверяет архивные метки подписи: для каждой пересчитывает то, что она
     * должна накрывать (свойства до неё самой), и прогоняет через строгую
     * проверку TSP. Меток нет — подтверждать нечего.
     */
    private fun archiveTimestampsValid(
        signatureElement: Element,
        checkOcsp: Boolean,
        checkCrl: Boolean,
    ): Boolean = try {
        val archives = XadesInspector.archiveTimestamps(signatureElement)
        archives.isNotEmpty() && archives.all { archive ->
            val token = XadesInspector.timestampToken(archive)
            if (token == null) {
                false
            } else {
                val input = XadesInspector.archiveTimestampInput(signatureElement, archive)
                tspService.verify(CMSSignedData(token), input, checkOcsp, checkCrl) != null
            }
        }
    } catch (e: Exception) {
        log.warn("Cannot verify the archive timestamp: {}", e.message)
        false
    }

    /**
     * До какого уровня подпись **подтверждена**. Каждая ступень требует своего
     * доказательства: метки времени для T, использованного вшитого материала
     * для LT, проверенной архивной метки для LTA.
     */
    private fun verifiedLevel(
        claimed: AdesLevel,
        timestamped: Boolean,
        embeddedUsed: Boolean,
        archiveValid: Boolean,
    ): AdesLevel = when {
        claimed.isAtLeast(AdesLevel.LTA) && archiveValid && embeddedUsed -> AdesLevel.LTA
        claimed.isAtLeast(AdesLevel.LT) && embeddedUsed -> AdesLevel.LT
        claimed.isAtLeast(AdesLevel.T) && timestamped -> AdesLevel.T
        else -> AdesLevel.B
    }

    private fun signatureElements(document: DocumentWrapper): List<Element> {
        val nodes = document.document.getElementsByTagNameNS(DS_NAMESPACE, "Signature")
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }

    private fun toTspInfo(info: kz.gov.pki.kalkan.tsp.TimeStampTokenInfo): TspInfo = TspInfo(
        serialNumber = String(Hex.encode(info.serialNumber.toByteArray())),
        genTime = info.genTime,
        policy = info.policy,
        tsa = info.tsa?.toString(),
        tspHashAlgorithm = getHashingAlgorithmByOID(info.messageImprintAlgOID),
        hash = String(Hex.encode(info.messageImprintDigest)),
    )

    /**
     * Нереализованное отклоняется явно, а не выполняется «похоже»: клиент,
     * попросивший detached, не должен получить enveloped и считать, что
     * получил заказанное.
     */
    private fun requirePackagingSupported(packaging: SignaturePackaging) {
        if (packaging != SignaturePackaging.ENVELOPED) {
            throw ClientException("XAdES packaging $packaging is not supported yet, use ENVELOPED")
        }
    }

    private companion object {
        private val log = org.slf4j.LoggerFactory.getLogger(XadesService::class.java)

        /** Exclusive c14n — та же канонизация, что использует NCALayer. */
        const val CANONICALIZATION = XadesInspector.CANONICALIZATION
        const val DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
    }
}
