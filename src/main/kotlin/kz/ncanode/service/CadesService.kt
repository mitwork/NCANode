package kz.ncanode.service

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore
import kz.ncanode.ades.CadesAttributes
import kz.ncanode.ades.CadesInspector
import kz.ncanode.ades.CmsArchiveTimestamp
import kz.ncanode.ades.CmsValidationData
import kz.gov.pki.kalkan.asn1.cms.Attribute
import java.util.Date
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.CadesSignerInfo
import kz.ncanode.dto.request.CadesSignBatchRequest
import kz.ncanode.dto.request.CadesSignRequest
import kz.ncanode.dto.request.CadesVerifyBatchRequest
import kz.ncanode.dto.request.CadesVerifyRequest
import kz.ncanode.dto.response.CadesResponse
import kz.ncanode.dto.response.CadesSignBatchResponse
import kz.ncanode.dto.response.CadesVerificationBatchResponse
import kz.ncanode.dto.response.CadesVerificationResponse
import kz.ncanode.dto.tsp.TsaPolicy
import kz.ncanode.exception.ApplicationException
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.util.getTspHashAlgorithmByOid
import kz.ncanode.util.mapPartial
import kz.ncanode.wrapper.KalkanWrapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.ByteArrayOutputStream
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Подпись CAdES по ETSI EN 319 122-1.
 *
 * Отдельный сервис, а не расширение [kz.ncanode.service.CmsService]: у того
 * своя, исторически сложившаяся форма CMS (без AdES-атрибутов), и она
 * остаётся как есть: эндпойнты `/cms/sign` и `/cms/verify` не легаси и
 * продолжают работать по-прежнему. Здесь реализуется профиль AdES,
 * совместимый с NCALayer.
 *
 * Реализованы уровни B, T, LT и LTA. T достаётся поверх B почти без кода:
 * метка ставится ровно так же, как её ставит НУЦ — imprint по значению
 * подписи, алгоритм хэша выводится из сертификата подписанта (см.
 * [TspService.addTspToSigner]). LT добавляет материал для проверки в сам
 * `SignedData`, LTA — архивную метку `archive-timestamp-v3` поверх всего.
 */
@Service
class CadesService(
    private val kalkanWrapper: KalkanWrapper,
    private val tspService: TspService,
    private val cmsService: CmsService,
    private val validationDataService: ValidationDataService,
) {

    fun sign(request: CadesSignRequest): CadesResponse {
        val level = request.level
        requireImplemented(level)

        val data = decodeData(request.data)

        return try {
            val generator = CMSSignedDataGenerator()
            val certificates = mutableListOf<X509Certificate>()

            for (keyStore in kalkanWrapper.read(request.signers)) {
                val certificate = keyStore.certificate.x509Certificate
                addSigner(generator, keyStore.privateKey, certificate)
                certificates.add(certificate)
            }

            val chainStore = CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(certificates.distinct()),
                KalkanProvider.PROVIDER_NAME,
            )
            generator.addCertificatesAndCRLs(chainStore)

            var signed = generator.generate(
                CMSProcessableByteArray(data),
                !request.isDetached,
                KalkanProvider.PROVIDER_NAME,
            )

            signed = applyLevel(signed, certificates, level, request.tsaPolicy, data)

            CadesResponse(
                cms = Base64.getEncoder().encodeToString(signed.encoded),
                level = level,
            )
        } catch (e: ApplicationException) {
            // Осознанные 400 (плохой пароль p12, пустой ключ) не превращаем в 500.
            throw e
        } catch (e: Exception) {
            throw ServerException("Error signing CAdES: ${e.message}", e)
        }
    }

    /**
     * Проверяет CAdES и сообщает уровень.
     *
     * Криптография, цепочка, отзыв и строгая проверка метки времени целиком
     * переиспользуются из [CmsService.verify] — дублировать этот пласт ради
     * AdES незачем, он один и тот же. Здесь добавляется то, чего в нём нет:
     * определение заявленного уровня и сверка привязки `signingCertificateV2`.
     */
    /**
     * Добавляет подписанта к готовому контейнеру — подпись «вторым по
     * маршруту», когда первый подписал раньше и своего ключа уже не даст.
     *
     * Подписи параллельные (RFC 5652 §5.1: несколько `SignerInfo` над одним
     * содержимым), а не вложенные: второй подписант заверяет документ, а не
     * подпись первого.
     *
     * Что сохраняется: подписанные и неподписанные атрибуты прежних
     * подписантов, их метки времени и архивные метки, вшитый материал
     * проверки. [CadesSignRequest.level] относится к НОВОМУ подписанту;
     * итоговый уровень документа — минимум по всем, поэтому в ответе он
     * вычисляется по факту, а не берётся из запроса.
     */
    fun coSign(request: CadesSignRequest): CadesResponse {
        val cmsBytes = decodeCms(request.cms ?: throw ClientException("CMS argument not specified"))

        return try {
            val existing = CMSSignedData(cmsBytes)
            val content = existing.signedContent?.let { signedContent ->
                ByteArrayOutputStream().use { out ->
                    signedContent.write(out)
                    out.toByteArray()
                }
            } ?: decodeData(request.data)   // detached: содержимое приносит клиент

            // Прежние подписанты переезжают как есть — вместе со своими
            // атрибутами; трогать их нельзя, это чужие подписи.
            val generator = CMSSignedDataGenerator().apply { addSigners(existing.signerInfos) }
            val certificates = existing.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
                .getCertificates(null)
                .filterIsInstance<X509Certificate>()
                .toMutableList()

            val existingSignerCertificates = signerCertificates(existing)
            for (keyStore in kalkanWrapper.read(request.signers)) {
                val certificate = keyStore.certificate.x509Certificate
                warnIfSignsAgain(existingSignerCertificates, certificate, request.level)
                addSigner(generator, keyStore.privateKey, certificate)
                certificates.add(certificate)
            }

            var signed = generator.generate(
                CMSProcessableByteArray(content),
                existing.signedContent != null,
                KalkanProvider.PROVIDER_NAME,
            )
            signed = CmsValidationData.embed(
                signed,
                certificates.distinct(),
                emptyList(),
                emptyList(),
            )
            signed = applyLevel(
                signed,
                signerCertificates(signed),
                request.level,
                request.tsaPolicy,
                content,
                carried = CmsValidationData.extract(cmsBytes),
            )

            val encoded = signed.encoded
            CadesResponse(
                cms = Base64.getEncoder().encodeToString(encoded),
                level = documentLevel(encoded),
            )
        } catch (e: ApplicationException) {
            throw e
        } catch (e: Exception) {
            throw ServerException("Error co-signing CAdES: ${e.message}", e)
        }
    }

    /** Добавляет подписанта с полным набором подписанных атрибутов AdES. */
    private fun addSigner(
        generator: CMSSignedDataGenerator,
        privateKey: java.security.PrivateKey,
        certificate: X509Certificate,
    ) {
        val digestAlgorithmOid = getDigestAlgorithmOidBYSignAlgorithmOid(certificate.sigAlgOID)
        val signedAttributes = CadesAttributes.signedAttributes(
            certificate = certificate,
            digestAlgorithmOid = digestAlgorithmOid,
            provider = kalkanWrapper.kalkanProvider,
        )
        // Перегрузка с AttributeTable: генератор сам дополнит набор
        // обязательными contentType и messageDigest.
        generator.addSigner(
            privateKey,
            certificate,
            digestAlgorithmOid,
            signedAttributes,
            null as kz.gov.pki.kalkan.asn1.cms.AttributeTable?,
        )
    }

    /**
     * Предупреждает о подписи тем же сертификатом, что уже стоит в контейнере.
     *
     * Сам контейнер при этом корректен, но у таких подписей совпадает SID
     * (издатель плюс серийный номер), и проверяющий, который ищет подписанта
     * по нему, пересчитает архивную метку второй подписи по данным первой и
     * отвергнет её. Так ведёт себя валидатор НУЦ — проверено на паре
     * контейнеров, отличавшихся только этим. До уровня LTA архивной метки нет,
     * и проблема не возникает.
     */
    private fun warnIfSignsAgain(
        existing: List<X509Certificate>,
        certificate: X509Certificate,
        level: AdesLevel,
    ) {
        if (!level.isAtLeast(AdesLevel.LTA)) return
        val alreadySigned = existing.any {
            it.serialNumber == certificate.serialNumber &&
                it.issuerX500Principal == certificate.issuerX500Principal
        }
        if (!alreadySigned) return

        log.warn(
            "Certificate {} has already signed this container; validators that resolve signers by " +
                "certificate id will reject the archive timestamp of the new signature",
            certificate.subjectX500Principal,
        )
    }

    /** Сертификаты всех подписантов контейнера — по их SID. */
    private fun signerCertificates(signed: CMSSignedData): List<X509Certificate> =
        signed.signerInfos.signers.mapNotNull { signerCertificateOf(signed, it as SignerInformation) }

    /**
     * Уровень документа — минимум по подписантам: контейнер не «долгоживущий»,
     * если хотя бы одна подпись в нём таковой не является.
     */
    private fun documentLevel(cms: ByteArray): AdesLevel? =
        CadesInspector.inspect(cms, kalkanWrapper.kalkanProvider)
            .minByOrNull { it.level.ordinal }?.level

    fun verify(request: CadesVerifyRequest): CadesVerificationResponse {
        val cmsBytes = decodeCms(request.cms)
        val provider = kalkanWrapper.kalkanProvider

        val facts = try {
            CadesInspector.inspect(cmsBytes, provider)
        } catch (e: Exception) {
            // Разбор AdES-специфики не должен ронять проверку подписи: базовый
            // вердикт получим и без него, просто не сможем назвать уровень.
            log.warn("Cannot inspect CAdES structure: {}", e.message)
            emptyList()
        }

        // Вшитый материал разбираем заранее: он понадобится до того, как
        // CmsService пойдёт за живыми данными.
        val embedded = if (facts.any { it.level.isAtLeast(AdesLevel.LT) }) {
            try {
                CmsValidationData.extract(cmsBytes)
            } catch (e: Exception) {
                log.warn("Cannot read the embedded validation data: {}", e.message)
                null
            }
        } else {
            null
        }

        val cms = CMSSignedData(cmsBytes)
        val signers = cms.signerInfos.signers.map { it as SignerInformation }
        val proofTimes = signers.associate { it.sid to proofOfExistence(it) }
        val verifiedBySerial = mutableMapOf<java.math.BigInteger, Boolean>()

        // Вшитый материал имеет смысл подставлять только если проверку отзыва
        // вообще запросили: иначе isValid его не посмотрит, и объявлять уровень
        // подтверждённым было бы неправдой.
        val revocationRequested = request.checkOcsp || request.checkCrl

        val base = cmsService.verify(request.cms, request.data, request.checkOcsp, request.checkCrl) { wrapper ->
            if (embedded == null || !revocationRequested) return@verify
            // Момент проверки — доказанное время существования подписи, а не
            // «сейчас». Данные об отзыве авторитетны только на своём интервале,
            // поэтому именно он и определяет, какой источник подойдёт.
            val at = proofTimes.values.filterNotNull().minOrNull() ?: Date()
            val answered = validationDataService.attachEmbedded(
                wrapper, embedded.crls, embedded.ocspResponses, at,
            )
            verifiedBySerial[wrapper.x509Certificate.serialNumber] = answered
        }

        // Для отсоединённой подписи содержимое приносит клиент — без него
        // архивную метку пересчитать не над чем.
        val content = cms.signedContent?.content as? ByteArray
            ?: request.data?.let { decodeData(it) }

        val archiveVerified = signers.mapIndexed { index, signer ->
            index to archiveTimestampsValid(cms, signer, request.checkOcsp, request.checkCrl, content)
        }.toMap()

        val verified = base.signers.mapIndexed { index, info ->
            val signerFacts = facts.getOrNull(index)
            val serial = info.certificates.firstOrNull()?.serialNumber
            CadesSignerInfo(
                level = signerFacts?.level,
                verifiedLevel = signerFacts?.level?.let { claimed ->
                    verifiedLevel(
                        claimed = claimed,
                        timestamped = info.tsp != null,
                        embeddedUsed = verifiedBySerial.values.any { it },
                        archiveValid = archiveVerified[index] == true,
                    )
                },
                certificates = info.certificates,
                tsp = info.tsp,
            )
        }

        val bindingsValid = facts.all { it.signingCertificateMatches }

        return CadesVerificationResponse(
            valid = base.valid && bindingsValid,
            level = verified.mapNotNull { it.level }.minByOrNull { it.ordinal },
            verifiedLevel = verified.mapNotNull { it.verifiedLevel }.minByOrNull { it.ordinal },
            signers = verified,
        )
    }

    /**
     * Доказанное время существования подписи: genTime её метки времени, если
     * метка есть. Иначе null — момент проверки остаётся текущим.
     */

    /**
     * Batch-подпись: каждый элемент подписывается независимо общим набором
     * signer'ов до общего уровня. Ошибка на одном элементе не валит остальные,
     * её видно в `results[n].status` (batch-инварианты — в CLAUDE.md).
     *
     * Уровень общий на весь batch: смешивать в одном запросе B и LTA незачем.
     */
    fun signBatch(request: CadesSignBatchRequest): CadesSignBatchResponse {
        val items = request.data.mapPartial({ status, message ->
            CadesSignBatchResponse.Item(status = status, message = message)
        }) { data ->
            val response = sign(
                CadesSignRequest().apply {
                    this.data = data
                    this.signers = request.signers
                    this.level = request.level
                    this.isDetached = request.isDetached
                    this.tsaPolicy = request.tsaPolicy
                },
            )
            CadesSignBatchResponse.Item(cms = response.cms, level = response.level)
        }
        return CadesSignBatchResponse(results = items)
    }

    /**
     * Batch-проверка: каждая пара `cms + data?` проверяется независимо
     * с общими revocation-флагами.
     */
    fun verifyBatch(request: CadesVerifyBatchRequest): CadesVerificationBatchResponse {
        val items = request.items.mapPartial({ status, message ->
            CadesVerificationResponse(valid = false, status = status, message = message)
        }) { item ->
            verify(
                CadesVerifyRequest().apply {
                    cms = item.cms
                    data = item.data
                    revocationCheck = request.revocationCheck
                },
            )
        }
        return CadesVerificationBatchResponse(results = items)
    }

    private fun proofOfExistence(signer: SignerInformation): Date? = try {
        tspService.extractTimestampToken(signer)
            ?.let { tspService.verify(it, signer.signature, false, false) }
            ?.genTime
    } catch (e: Exception) {
        log.warn("Cannot read the signature timestamp: {}", e.message)
        null
    }

    /**
     * Проверяет архивные метки подписанта: пересчитывает то, что метка должна
     * накрывать, и прогоняет её через строгую проверку TSP. Если меток нет —
     * `false`: подтверждать нечего.
     */
    private fun archiveTimestampsValid(
        cms: CMSSignedData,
        signer: SignerInformation,
        checkOcsp: Boolean,
        checkCrl: Boolean,
        content: ByteArray?,
    ): Boolean = try {
        val provider = kalkanWrapper.kalkanProvider
        val archives = signer.unsignedAttributes?.getAll(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3)
        if (content == null) {
            // Отсоединённая подпись без данных: пересчитать imprint не над чем,
            // а объявлять метку проверенной на основании пустоты нельзя.
            log.warn("Cannot verify the archive timestamp: the detached content was not provided")
            false
        } else if (archives == null || archives.size() == 0) {
            false
        } else {
            (0 until archives.size()).all { index ->
                val attribute = Attribute.getInstance(archives.get(index))
                val tokenCms = CMSSignedData(
                    attribute.attrValues.getObjectAt(0).getDERObject().getDEREncoded(),
                )
                val hashIndex = (tokenCms.signerInfos.signers.first() as SignerInformation)
                    .unsignedAttributes?.get(CmsArchiveTimestamp.ATS_HASH_INDEX_V3)
                if (hashIndex == null) {
                    log.warn("Archive timestamp has no ATSHashIndex — cannot verify what it covers")
                    false
                } else {
                    val digestOid = getTspHashAlgorithmByOid(
                        signerCertificateOf(cms, signer)?.sigAlgOID ?: return@all false,
                    )
                    val input =
                        CmsArchiveTimestamp.imprintInput(cms, signer, digestOid, hashIndex, provider, content)
                    tspService.verify(tokenCms, input, checkOcsp, checkCrl) != null
                }
            }
        }
    } catch (e: Exception) {
        log.warn("Cannot verify the archive timestamp: {}", e.message)
        false
    }

    private fun signerCertificateOf(cms: CMSSignedData, signer: SignerInformation): X509Certificate? = try {
        cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME)
            .getCertificates(signer.sid)
            .filterIsInstance<X509Certificate>()
            .firstOrNull()
    } catch (e: Exception) {
        null
    }

    /**
     * До какого уровня подпись реально **подтверждена** — в отличие от того,
     * какой она заявляет. Каждая ступень требует своего доказательства: метки
     * времени для T, использованного вшитого материала для LT, проверенной
     * архивной метки для LTA. Не подтвердилось — уровень ниже, и клиент это
     * видит.
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

    private fun decodeCms(cms: String): ByteArray = try {
        Base64.getDecoder().decode(cms)
    } catch (e: IllegalArgumentException) {
        throw ClientException("CMS is not valid base64")
    }

    /**
     * Встраивает в подпись цепочки и данные об отзыве — уровень LT.
     *
     * Материал собирается на текущий момент. Для только что созданной подписи
     * это совпадает с genTime её метки времени; при повышении уровня у старой
     * подписи (операция extend, пока не реализована) момент сбора должен
     * задаваться отдельно.
     */
    /**
     * Надстраивает уровни поверх готового `SignedData`.
     *
     * [carried] — материал проверки, уже лежавший в контейнере до нашего
     * вмешательства. Его переносим ВСЕГДА, независимо от запрошенного уровня:
     * иначе доподписание молча превращало бы LT-подпись в обычную, оставляя её
     * валидной и уже недолгоживущей — ровно та ловушка, что есть у старого
     * `PATCH /cms/sign`.
     */
    private fun applyLevel(
        signed: CMSSignedData,
        certificates: List<X509Certificate>,
        level: AdesLevel,
        tsaPolicy: TsaPolicy?,
        content: ByteArray,
        carried: CmsValidationData.Embedded? = null,
    ): CMSSignedData {
        var result = signed
        if (level.isAtLeast(AdesLevel.T)) {
            result = addSignatureTimestamps(result, tsaPolicy)
        }
        if (level.isAtLeast(AdesLevel.LT)) {
            result = embedValidationData(result, certificates, carried)
        } else if (carried != null && (carried.crls.isNotEmpty() || carried.ocspResponses.isNotEmpty())) {
            result = CmsValidationData.embed(result, emptyList(), carried.crls, carried.ocspResponses)
        }
        if (level.isAtLeast(AdesLevel.LTA)) {
            result = addArchiveTimestamps(result, tsaPolicy, content)
        }
        return result
    }

    private fun embedValidationData(
        signed: CMSSignedData,
        certificates: List<X509Certificate>,
        carried: CmsValidationData.Embedded? = null,
    ): CMSSignedData {
        val chain = mutableListOf<X509Certificate>()
        val crls = mutableListOf<java.security.cert.X509CRL>()
        val ocspResponses = mutableListOf<ByteArray>()

        carried?.let {
            crls.addAll(it.crls)
            ocspResponses.addAll(it.ocspResponses)
        }

        for (certificate in certificates.distinct()) {
            val data = validationDataService.collect(certificate)
            chain.addAll(data.certificates)
            crls.addAll(data.crls)
            ocspResponses.addAll(data.ocspResponses)
        }

        return CmsValidationData.embed(
            signed,
            chain.distinct(),
            crls.distinctBy { it.encoded.contentHashCode() },
            ocspResponses.distinctBy { it.contentHashCode() },
        )
    }

    /**
     * Ставит архивную метку времени поверх подписи и всего вшитого материала
     * — уровень LTA.
     *
     * Порядок обязателен: метка считается по текущему состоянию подписи,
     * поэтому сначала должны быть добавлены и метка времени подписи (T), и
     * данные для проверки (LT). Иначе она зафиксирует неполную картину.
     */
    /**
     * Добавляет архивную метку тем подписантам, у кого её ещё нет.
     *
     * У существующих метка уже накрыла их состояние на своё время, и вторая им
     * ничего не добавит: индекс `ATSHashIndex-v3` перечисляет то, что метка
     * покрыла, и появление нового подписанта его не ломает.
     */
    private fun addArchiveTimestamps(
        signed: CMSSignedData,
        tsaPolicy: TsaPolicy?,
        content: ByteArray,
    ): CMSSignedData {
        val policyId = (tsaPolicy ?: TsaPolicy.TSA_GOST2015_POLICY).policyId
        val provider = kalkanWrapper.kalkanProvider

        val archived = signed.signerInfos.signers.map { signerObject ->
            val signer = signerObject as SignerInformation
            val certificate = signerCertificateOf(signed, signer)

            if (certificate == null || hasArchiveTimestamp(signer)) {
                signer
            } else {
                val digestOid = getTspHashAlgorithmByOid(certificate.sigAlgOID)
                val hashIndex = CmsArchiveTimestamp.hashIndex(signed, signer, digestOid, provider)
                val imprintInput =
                    CmsArchiveTimestamp.imprintInput(signed, signer, digestOid, hashIndex, provider, content)
                val token = tspService.create(imprintInput, digestOid, policyId)
                CmsArchiveTimestamp.attach(signer, CmsArchiveTimestamp.embedHashIndex(token, hashIndex))
            }
        }

        return CMSSignedData.replaceSigners(signed, SignerInformationStore(archived))
    }

    private fun hasArchiveTimestamp(signer: SignerInformation): Boolean =
        signer.unsignedAttributes?.get(CmsArchiveTimestamp.ARCHIVE_TIMESTAMP_V3) != null

    /**
     * Ставит метку времени тем подписантам, у кого её ещё нет.
     *
     * Сертификат ищется по SID подписанта, а не по позиции: при доподписании
     * порядок подписантов и порядок сертификатов в контейнере уже не совпадают.
     * Пропуск уже проштампованных — тоже про доподписание: вторая метка поверх
     * чужой подписи означала бы, что мы задним числом свидетельствуем о времени,
     * которого не наблюдали.
     */
    private fun addSignatureTimestamps(signed: CMSSignedData, tsaPolicy: TsaPolicy?): CMSSignedData {
        val policyId = (tsaPolicy ?: TsaPolicy.TSA_GOST2015_POLICY).policyId
        val timestamped = signed.signerInfos.signers.map { signerObject ->
            val signer = signerObject as SignerInformation
            val certificate = signerCertificateOf(signed, signer)
            if (certificate == null || tspService.hasTimestampAttribute(signer)) {
                signer
            } else {
                tspService.addTspToSigner(signer, certificate, policyId)
            }
        }
        return CMSSignedData.replaceSigners(signed, SignerInformationStore(timestamped))
    }

    private fun decodeData(data: String?): ByteArray {
        val encoded = data ?: throw ClientException("Data argument not specified")
        return try {
            Base64.getDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw ClientException("Data is not valid base64")
        }
    }

    private fun requireImplemented(level: AdesLevel) {
        // Все четыре уровня реализованы; метод оставлен как точка отказа для
        // будущих значений перечисления.
    }

    companion object {
        private val log = LoggerFactory.getLogger(CadesService::class.java)
    }
}
