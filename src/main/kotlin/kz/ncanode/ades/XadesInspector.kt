package kz.ncanode.ades

import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.util.getDigestAlgorithmOidBYSignAlgorithmOid
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.apache.xml.security.algorithms.JCEMapper
import org.apache.xml.security.c14n.Canonicalizer
import org.slf4j.LoggerFactory
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.Provider
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Разбор XAdES-специфики подписи: заявленный уровень, привязка к сертификату
 * и метка времени.
 *
 * Как и в CAdES, уровень определяется **наличием элементов, а не их
 * валидностью** — по правилам валидатора НУЦ
 * (`XadesSignatureService.validateSignatureElement`):
 *
 *  1. B — базовый;
 *  2. T — присутствует `xades:SignatureTimeStamp`;
 *  3. LT — присутствует `xades:CertificateValues`;
 *  4. LTA — присутствует `xades141:ArchiveTimeStamp`.
 */
object XadesInspector {

    /** Exclusive c14n — канонизация, которую использует NCALayer. */
    const val CANONICALIZATION = "http://www.w3.org/2001/10/xml-exc-c14n#"

    private const val XADES_NAMESPACE = XadesQualifyingProperties.XADES_NAMESPACE
    private const val XADES141_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#"
    private const val DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"

    /** Факты об одной подписи. */
    data class SignatureFacts(
        val level: AdesLevel,
        /** Сошёлся ли `CertDigest` с сертификатом из `KeyInfo`. `true`, если свойств нет. */
        val signingCertificateMatches: Boolean,
        /** Токен метки времени, если подпись заявляет уровень T. */
        val timestampToken: CMSSignedData? = null,
    )

    /**
     * Байты, которые накрывает метка времени XAdES: канонизированный элемент
     * `ds:SignatureValue` (EN 319 132-1).
     *
     * Одно определение на подпись и на проверку намеренно: разъехавшись, они
     * дали бы метку, которая ставится над одним, а проверяется над другим —
     * и ошибка вылезла бы только на чужой реализации.
     */
    fun timestampedBytes(signatureElement: Element): ByteArray {
        val signatureValue = firstDescendant(signatureElement, DS_NAMESPACE, "SignatureValue")
            ?: error("No ds:SignatureValue in signature")
        return canonicalize(signatureValue)
    }

    /**
     * Данные, по которым считается архивная метка времени (EN 319 132-1 §5.5.2).
     *
     * Метка накрывает подпись целиком вместе со всем, что к ней уже
     * добавлено: содержимое всех ссылок после трансформаций, `SignedInfo`,
     * значение подписи, `KeyInfo`, ранее добавленные неподписанные свойства и
     * посторонние `ds:Object`. Именно поэтому она и защищает от устаревания
     * алгоритмов — фиксирует всю картину, а не только подпись.
     *
     * Сам `ds:Object` с `QualifyingProperties` исключается: он содержит и эту
     * метку тоже, расчёт стал бы рекурсивным.
     *
     * [boundary] — проверяемая архивная метка: перебор неподписанных свойств
     * обрывается на ней. При выпуске новой метки границы нет.
     */
    fun archiveTimestampInput(signatureElement: Element, boundary: Element? = null): ByteArray {
        val out = ByteArrayOutputStream()
        // Через обёртку, а не напрямую: она регистрирует Id у XAdES-свойств,
        // без чего ссылка на SignedProperties не резолвится в разобранном
        // документе и содержимое ссылок не получить.
        val signature = XMLSignatureWrapper(signatureElement).xmlSignature

        val signedInfo = signature.signedInfo
        for (index in 0 until signedInfo.length) {
            out.write(signedInfo.item(index).contentsAfterTransformation.bytes)
        }

        out.write(canonicalize(firstDescendant(signatureElement, DS_NAMESPACE, "SignedInfo")!!))
        out.write(canonicalize(firstDescendant(signatureElement, DS_NAMESPACE, "SignatureValue")!!))
        firstDescendant(signatureElement, DS_NAMESPACE, "KeyInfo")?.let { out.write(canonicalize(it)) }

        // Уже добавленные неподписанные свойства — в порядке появления.
        val properties = firstDescendant(signatureElement, XADES_NAMESPACE, "UnsignedSignatureProperties")
        if (properties != null) {
            val children = properties.childNodes
            for (index in 0 until children.length) {
                val child = children.item(index)
                // При проверке останавливаемся на самой проверяемой метке:
                // всё, что добавлено после неё (включая её саму), она накрывать
                // не может. При выпуске границы нет — метки ещё не существует.
                if (child === boundary) break
                (child as? Element)?.let { out.write(canonicalize(it)) }
            }
        }

        val objects = signatureElement.getElementsByTagNameNS(DS_NAMESPACE, "Object")
        for (index in 0 until objects.length) {
            val objectElement = objects.item(index) as Element
            if (firstDescendant(objectElement, XADES_NAMESPACE, "QualifyingProperties") == null) {
                out.write(canonicalize(objectElement))
            }
        }

        return out.toByteArray()
    }

    fun inspect(
        signatureElement: Element,
        certificate: X509Certificate?,
        provider: Provider,
    ): SignatureFacts {
        val timestamp = firstDescendant(signatureElement, XADES_NAMESPACE, "SignatureTimeStamp")

        var level = AdesLevel.B
        if (timestamp != null) {
            level = AdesLevel.T
        }
        if (firstDescendant(signatureElement, XADES_NAMESPACE, "CertificateValues") != null) {
            level = AdesLevel.LT
        }
        if (firstDescendant(signatureElement, XADES141_NAMESPACE, "ArchiveTimeStamp") != null) {
            level = AdesLevel.LTA
        }

        return SignatureFacts(
            level = level,
            signingCertificateMatches = signingCertificateMatches(signatureElement, certificate, provider),
            timestampToken = timestamp?.let { encapsulatedToken(it) },
        )
    }

    /**
     * Сверяет `xades:CertDigest` из подписанных свойств с сертификатом
     * подписанта.
     *
     * Это единственное, что уровень B добавляет к обычному XMLDSIG: свойства
     * лежат под подписью и привязывают её к конкретному сертификату. Не
     * проверять их — значит принимать заявленный уровень, ничего не подтвердив.
     */
    private fun signingCertificateMatches(
        signatureElement: Element,
        certificate: X509Certificate?,
        provider: Provider,
    ): Boolean {
        val certDigest = firstDescendant(signatureElement, XADES_NAMESPACE, "CertDigest") ?: return true
        if (certificate == null) {
            log.warn("XAdES CertDigest present but the signing certificate is missing from KeyInfo")
            return false
        }

        val digestValue = firstDescendant(certDigest, DS_NAMESPACE, "DigestValue")?.textContent?.trim()
        if (digestValue.isNullOrEmpty()) {
            log.warn("XAdES CertDigest has no DigestValue")
            return false
        }
        val algorithmUri = firstDescendant(certDigest, DS_NAMESPACE, "DigestMethod")?.getAttribute("Algorithm")

        return try {
            val digest = digestOf(certificate, algorithmUri, provider)
            val matches = digest.contentEquals(Base64.getDecoder().decode(digestValue))
            if (!matches) {
                log.warn("XAdES CertDigest does not match the signing certificate")
            }
            matches
        } catch (e: Exception) {
            log.warn("Cannot verify XAdES CertDigest: {}", e.message)
            false
        }
    }

    /**
     * Считает хэш сертификата алгоритмом из `ds:DigestMethod`. Если URI
     * неизвестен Santuario, берём алгоритм самого сертификата — именно его
     * там и указывает NCALayer.
     */
    private fun digestOf(certificate: X509Certificate, algorithmUri: String?, provider: Provider): ByteArray {
        val jceName = algorithmUri?.takeIf { it.isNotEmpty() }?.let { JCEMapper.translateURItoJCEID(it) }
            ?: getDigestAlgorithmOidBYSignAlgorithmOid(certificate.sigAlgOID)
        return MessageDigest.getInstance(jceName, provider).digest(certificate.encoded)
    }

    private fun encapsulatedToken(timestamp: Element): CMSSignedData? = try {
        val encoded = firstDescendant(timestamp, XADES_NAMESPACE, "EncapsulatedTimeStamp")?.textContent?.trim()
        encoded?.takeIf { it.isNotEmpty() }?.let { CMSSignedData(Base64.getDecoder().decode(it)) }
    } catch (e: Exception) {
        log.warn("Cannot read xades:EncapsulatedTimeStamp: {}", e.message)
        null
    }

    /** Архивные метки подписи в порядке добавления. */
    fun archiveTimestamps(signatureElement: Element): List<Element> {
        val nodes = signatureElement.getElementsByTagNameNS(XADES141_NAMESPACE, "ArchiveTimeStamp")
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }

    /** Токен метки времени из элемента `*TimeStamp`. */
    fun timestampToken(timestampElement: Element): ByteArray? =
        firstDescendant(timestampElement, XADES_NAMESPACE, "EncapsulatedTimeStamp")
            ?.textContent?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let { Base64.getDecoder().decode(it) }

    /** Материал для проверки, вшитый в подпись (уровень LT и данные меток). */
    class EmbeddedMaterial(
        val certificates: List<X509Certificate>,
        val crls: List<X509CRL>,
        val ocspResponses: List<ByteArray>,
    )

    /**
     * Достаёт вшитый материал: цепочки из `CertificateValues`, списки отзыва и
     * ответы респондера из `RevocationValues`, а также то же самое из
     * `TimeStampValidationData` — оно нужно для проверки самих меток.
     *
     * Только достаёт; доверять нельзя — подписи проверяются при вынесении
     * вердикта.
     */
    fun embeddedMaterial(signatureElement: Element): EmbeddedMaterial {
        val factory = CertificateFactory.getInstance("X.509")

        val certificates = encodedValues(signatureElement, "EncapsulatedX509Certificate").mapNotNull {
            runCatching { factory.generateCertificate(it.inputStream()) as X509Certificate }
                .onFailure { error -> log.warn("Cannot read an embedded certificate: {}", error.message) }
                .getOrNull()
        }
        val crls = encodedValues(signatureElement, "EncapsulatedCRLValue").mapNotNull {
            runCatching { factory.generateCRL(it.inputStream()) as X509CRL }
                .onFailure { error -> log.warn("Cannot read an embedded CRL: {}", error.message) }
                .getOrNull()
        }
        val ocspResponses = encodedValues(signatureElement, "EncapsulatedOCSPValue")

        return EmbeddedMaterial(certificates, crls, ocspResponses)
    }

    private fun encodedValues(context: Element, name: String): List<ByteArray> {
        val nodes = context.getElementsByTagNameNS(XADES_NAMESPACE, name)
        return (0 until nodes.length).mapNotNull { index ->
            val text = (nodes.item(index) as Element).textContent?.trim()
            if (text.isNullOrEmpty()) null else runCatching { Base64.getDecoder().decode(text) }.getOrNull()
        }
    }

    private fun firstDescendant(context: Element, namespace: String, name: String): Element? {
        val nodes = context.getElementsByTagNameNS(namespace, name)
        return if (nodes.length == 0) null else nodes.item(0) as Element
    }

    private fun canonicalize(node: Node): ByteArray {
        val output = ByteArrayOutputStream()
        Canonicalizer.getInstance(CANONICALIZATION).canonicalizeSubtree(node, output)
        return output.toByteArray()
    }

    private val log = LoggerFactory.getLogger(XadesInspector::class.java)
}
