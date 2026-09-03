package kz.ncanode.ades

import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.DERInteger
import kz.gov.pki.kalkan.asn1.x509.GeneralName
import kz.gov.pki.kalkan.asn1.x509.GeneralNames
import kz.gov.pki.kalkan.asn1.x509.IssuerSerial
import kz.gov.pki.kalkan.asn1.x509.X509Name
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.security.MessageDigest
import java.security.Provider
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.TimeZone

/**
 * Построение `xades:QualifyingProperties` уровня XAdES-B
 * (ETSI EN 319 132-1).
 *
 * Структура сверена с реализацией НУЦ
 * (согласно реализации NCALayer) — цель не
 * «соответствовать стандарту вообще», а совпасть с тем, что выпускает и
 * принимает официальный клиент:
 *
 * ```xml
 * <xades:QualifyingProperties Target="#sig-...">
 *   <xades:SignedProperties Id="sig-...-signedprops">
 *     <xades:SignedSignatureProperties>
 *       <xades:SigningTime>2026-08-26T09:12:33Z</xades:SigningTime>
 *       <xades:SigningCertificateV2>
 *         <xades:Cert>
 *           <xades:CertDigest>
 *             <ds:DigestMethod Algorithm="..."/><ds:DigestValue>...</ds:DigestValue>
 *           </xades:CertDigest>
 *           <xades:IssuerSerialV2>...</xades:IssuerSerialV2>
 *         </xades:Cert>
 *       </xades:SigningCertificateV2>
 *     </xades:SignedSignatureProperties>
 *     <xades:SignedDataObjectProperties>
 *       <xades:DataObjectFormat ObjectReference="#sig-...-ref0">
 *         <xades:MimeType>text/xml</xades:MimeType>
 *       </xades:DataObjectFormat>
 *     </xades:SignedDataObjectProperties>
 *   </xades:SignedProperties>
 * </xades:QualifyingProperties>
 * ```
 *
 * Важное отличие от CAdES: там хэш сертификата всегда SHA-256, а здесь
 * `CertDigest` считается **тем же алгоритмом, которым подписывается документ**
 * — для GOST-ключа это GOST.
 */
object XadesQualifyingProperties {

    const val XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#"
    const val SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"

    private const val DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
    private const val XADES141_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#"
    private const val XMLNS_NAMESPACE = "http://www.w3.org/2000/xmlns/"
    private const val PREFIX = "xades"
    private const val MIME_TYPE = "text/xml"

    /**
     * Собирает `QualifyingProperties` для подписи [signatureId].
     *
     * @param digestUri XML-идентификатор алгоритма хэширования (идёт в
     *   `ds:DigestMethod`)
     * @param digestOid OID того же алгоритма — им считается сам хэш
     * @param dataReferenceId Id ссылки на подписываемые данные, на неё
     *   указывает `DataObjectFormat`
     */
    fun build(
        document: Document,
        certificate: X509Certificate,
        signatureId: String,
        signedPropertiesId: String,
        dataReferenceId: String,
        digestUri: String,
        digestOid: String,
        provider: Provider,
        signingTime: Date = Date(),
    ): Element {
        val qualifyingProperties = document.createElementNS(XADES_NAMESPACE, "$PREFIX:QualifyingProperties")
        qualifyingProperties.setAttributeNS(XMLNS_NAMESPACE, "xmlns:$PREFIX", XADES_NAMESPACE)
        qualifyingProperties.setAttribute("Target", "#$signatureId")

        val signedProperties = element(document, "SignedProperties")
        signedProperties.setAttribute("Id", signedPropertiesId)
        // Без этого Santuario не разрешит ссылку "#signedPropertiesId" при
        // подсчёте дайджеста: атрибут должен быть объявлен как ID.
        signedProperties.setIdAttribute("Id", true)

        val signedSignatureProperties = element(document, "SignedSignatureProperties")
        val signingTimeElement = element(document, "SigningTime")
        signingTimeElement.textContent = iso8601Utc(signingTime)
        signedSignatureProperties.appendChild(signingTimeElement)
        signedSignatureProperties.appendChild(
            signingCertificateV2(document, certificate, digestUri, digestOid, provider),
        )

        signedProperties.appendChild(signedSignatureProperties)
        signedProperties.appendChild(signedDataObjectProperties(document, dataReferenceId))
        qualifyingProperties.appendChild(signedProperties)

        return qualifyingProperties
    }

    private fun signingCertificateV2(
        document: Document,
        certificate: X509Certificate,
        digestUri: String,
        digestOid: String,
        provider: Provider,
    ): Element {
        val signingCertificate = element(document, "SigningCertificateV2")
        val cert = element(document, "Cert")

        val certDigest = element(document, "CertDigest")
        val digestMethod = document.createElementNS(DS_NAMESPACE, "ds:DigestMethod")
        digestMethod.setAttribute("Algorithm", digestUri)
        val digestValue = document.createElementNS(DS_NAMESPACE, "ds:DigestValue")
        digestValue.textContent = Base64.getEncoder()
            .encodeToString(MessageDigest.getInstance(digestOid, provider).digest(certificate.encoded))
        certDigest.appendChild(digestMethod)
        certDigest.appendChild(digestValue)

        val issuerSerial = element(document, "IssuerSerialV2")
        issuerSerial.textContent = Base64.getEncoder().encodeToString(issuerSerialV2(certificate))

        cert.appendChild(certDigest)
        cert.appendChild(issuerSerial)
        signingCertificate.appendChild(cert)
        return signingCertificate
    }

    private fun signedDataObjectProperties(document: Document, dataReferenceId: String): Element {
        val properties = element(document, "SignedDataObjectProperties")
        val dataObjectFormat = element(document, "DataObjectFormat")
        dataObjectFormat.setAttribute("ObjectReference", "#$dataReferenceId")
        val mimeType = element(document, "MimeType")
        mimeType.textContent = MIME_TYPE
        dataObjectFormat.appendChild(mimeType)
        properties.appendChild(dataObjectFormat)
        return properties
    }

    /** DER-кодированный `IssuerSerial` (RFC 5035) — издатель плюс серийный номер. */
    private fun issuerSerialV2(certificate: X509Certificate): ByteArray {
        val issuer = X509Name.getInstance(ASN1Object.fromByteArray(certificate.issuerX500Principal.encoded))
        val names = GeneralNames(GeneralName(issuer))
        return IssuerSerial(names, DERInteger(certificate.serialNumber)).getEncoded()
    }

    /** `xades:SigningTime` — UTC с секундами, как его выдаёт NCALayer. */
    private fun iso8601Utc(date: Date): String {
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
        format.timeZone = TimeZone.getTimeZone("UTC")
        return format.format(date)
    }

    /**
     * Возвращает (создавая при необходимости) `UnsignedSignatureProperties`
     * внутри уже существующих `QualifyingProperties`.
     *
     * Эти свойства НЕ покрыты ни одной `ds:Reference`, поэтому их можно
     * добавлять уже после подписания — на чём и держится надстройка уровней:
     * метка времени появляется поверх готовой подписи, не ломая её.
     */
    fun unsignedSignatureProperties(qualifyingProperties: Element): Element {
        val document = qualifyingProperties.ownerDocument
        val unsigned = firstChild(qualifyingProperties, "UnsignedProperties")
            ?: element(document, "UnsignedProperties").also { qualifyingProperties.appendChild(it) }
        return firstChild(unsigned, "UnsignedSignatureProperties")
            ?: element(document, "UnsignedSignatureProperties").also { unsigned.appendChild(it) }
    }

    /**
     * `xades:SignatureTimeStamp` с указанием канонизации и самим токеном
     * (RFC 3161) в base64 — в точности та форма, что у NCALayer.
     */
    fun signatureTimeStamp(document: Document, token: ByteArray, canonicalization: String): Element {
        val timeStamp = element(document, "SignatureTimeStamp")

        val method = document.createElementNS(DS_NAMESPACE, "ds:CanonicalizationMethod")
        method.setAttribute("Algorithm", canonicalization)
        timeStamp.appendChild(method)

        val encapsulated = element(document, "EncapsulatedTimeStamp")
        encapsulated.textContent = Base64.getEncoder().encodeToString(token)
        timeStamp.appendChild(encapsulated)

        return timeStamp
    }

    /**
     * `xades:CertificateValues` — цепочка сертификатов внутри подписи
     * (XAdES-LT, EN 319 132-1).
     */
    fun certificateValues(document: Document, certificates: List<X509Certificate>): Element {
        val values = element(document, "CertificateValues")
        for (certificate in certificates) {
            val encapsulated = element(document, "EncapsulatedX509Certificate")
            encapsulated.textContent = Base64.getEncoder().encodeToString(certificate.encoded)
            values.appendChild(encapsulated)
        }
        return values
    }

    /**
     * `xades:RevocationValues` — CRL'и и OCSP-ответы внутри подписи. Пустые
     * контейнеры не создаются: `CRLValues` без единого значения не несёт
     * смысла и мешает разбору.
     */
    fun revocationValues(document: Document, crls: List<X509CRL>, ocspResponses: List<ByteArray>): Element {
        val values = element(document, "RevocationValues")

        if (crls.isNotEmpty()) {
            val crlValues = element(document, "CRLValues")
            for (crl in crls) {
                val encapsulated = element(document, "EncapsulatedCRLValue")
                encapsulated.textContent = Base64.getEncoder().encodeToString(crl.encoded)
                crlValues.appendChild(encapsulated)
            }
            values.appendChild(crlValues)
        }

        if (ocspResponses.isNotEmpty()) {
            val ocspValues = element(document, "OCSPValues")
            for (response in ocspResponses) {
                val encapsulated = element(document, "EncapsulatedOCSPValue")
                encapsulated.textContent = Base64.getEncoder().encodeToString(response)
                ocspValues.appendChild(encapsulated)
            }
            values.appendChild(ocspValues)
        }

        return values
    }

    /**
     * `xades141:ArchiveTimeStamp` — архивная метка времени (XAdES-LTA).
     * Живёт в пространстве имён 1.4.1, в отличие от остальных свойств.
     */
    fun archiveTimeStamp(document: Document, token: ByteArray, canonicalization: String): Element {
        val archive = document.createElementNS(XADES141_NAMESPACE, "xades141:ArchiveTimeStamp")
        archive.setAttributeNS(XMLNS_NAMESPACE, "xmlns:xades141", XADES141_NAMESPACE)

        val method = document.createElementNS(DS_NAMESPACE, "ds:CanonicalizationMethod")
        method.setAttribute("Algorithm", canonicalization)
        archive.appendChild(method)

        val encapsulated = element(document, "EncapsulatedTimeStamp")
        encapsulated.textContent = Base64.getEncoder().encodeToString(token)
        archive.appendChild(encapsulated)

        return archive
    }

    /**
     * `xades141:TimeStampValidationData` — материал для проверки самой метки
     * времени. Без него архивная метка со временем стала бы непроверяемой:
     * сертификат TSA тоже истекает.
     */
    fun timeStampValidationData(
        document: Document,
        certificates: List<X509Certificate>,
        crls: List<X509CRL>,
        ocspResponses: List<ByteArray>,
    ): Element {
        val data = document.createElementNS(XADES141_NAMESPACE, "xades141:TimeStampValidationData")
        data.setAttributeNS(XMLNS_NAMESPACE, "xmlns:xades141", XADES141_NAMESPACE)

        if (certificates.isNotEmpty()) {
            data.appendChild(certificateValues(document, certificates))
        }
        if (crls.isNotEmpty() || ocspResponses.isNotEmpty()) {
            data.appendChild(revocationValues(document, crls, ocspResponses))
        }
        return data
    }

    private fun firstChild(parent: Element, name: String): Element? {
        val children = parent.childNodes
        for (i in 0 until children.length) {
            val child = children.item(i) as? Element ?: continue
            if (child.namespaceURI == XADES_NAMESPACE && child.localName == name) return child
        }
        return null
    }

    private fun element(document: Document, name: String): Element =
        document.createElementNS(XADES_NAMESPACE, "$PREFIX:$name")
}
