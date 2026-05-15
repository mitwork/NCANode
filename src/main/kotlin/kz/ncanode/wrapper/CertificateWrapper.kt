package kz.ncanode.wrapper

import kz.gov.pki.kalkan.asn1.DERIA5String
import kz.gov.pki.kalkan.asn1.x509.AccessDescription
import kz.gov.pki.kalkan.asn1.x509.AuthorityInformationAccess
import kz.gov.pki.kalkan.asn1.x509.CRLDistPoint
import kz.gov.pki.kalkan.asn1.x509.DistributionPointName
import kz.gov.pki.kalkan.asn1.x509.GeneralName
import kz.gov.pki.kalkan.asn1.x509.GeneralNames
import kz.gov.pki.kalkan.asn1.x509.X509Extensions
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.x509.extension.X509ExtensionUtil
import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.certificate.CertificateKeyUsage
import kz.ncanode.dto.certificate.CertificateKeyUser
import kz.ncanode.dto.certificate.CertificateRevocationStatus
import kz.ncanode.dto.certificate.CertificateSubject
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.util.createNewUrl
import kz.ncanode.util.getSignMethodByOID
import org.bouncycastle.asn1.x509.Extension
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.net.URL
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PublicKey
import java.security.SignatureException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import javax.naming.InvalidNameException
import javax.naming.ldap.LdapName
import javax.security.auth.x500.X500Principal

class CertificateWrapper(val x509Certificate: X509Certificate) {

    var issuerCertificate: CertificateWrapper? = null
    var ocspStatus: List<OcspStatus>? = null
    var crlStatus: CrlStatus? = null

    private val signAlg: Array<String> = getSignMethodByOID(x509Certificate.sigAlgOID)

    /** ID алгоритма подписи. */
    val signAlgorithmId: String get() = signAlg[0]

    /** ID алгоритма хэширования. */
    val hashAlgorithmId: String get() = signAlg[1]

    /**
     * Создаёт объект CertificateInfo.
     */
    fun toCertificateInfo(date: Date, checkOcsp: Boolean, checkCrl: Boolean): CertificateInfo {
        val cert = x509Certificate

        val revocations = mutableListOf<CertificateRevocationStatus>()
        crlStatus?.let { revocations.add(it.toCertificateRevocationStatus()) }
        ocspStatus?.let { statuses -> revocations.addAll(statuses.map { it.toCertificateRevocationStatus() }) }

        return CertificateInfo(
            valid = isValid(date, checkOcsp, checkCrl),
            revocations = revocations,
            notBefore = cert.notBefore,
            notAfter = cert.notAfter,
            keyUsage = CertificateKeyUsage.fromKeyUsageBits(cert.keyUsage),
            serialNumber = cert.serialNumber.toString(16),
            signAlg = cert.sigAlgName,
            keyUser = keyUser,
            publicKey = String(Base64.getEncoder().encode(cert.publicKey.encoded)),
            signature = String(Base64.getEncoder().encode(cert.signature)),
            subject = createCertificateSubjectFromDn(cert.subjectX500Principal.toString(), extractSanEmail(cert)),
            issuer = createCertificateSubjectFromDn(cert.issuerX500Principal.toString(), null),
        )
    }

    /**
     * Получает список CRL DistributionPoint URL'ов сертификата.
     */
    val crlList: List<URL>
        get() {
            val crlDistributionPoint = x509Certificate.getExtensionValue(Extension.cRLDistributionPoints.id)
                ?: return emptyList()

            val distPoint = try {
                CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(crlDistributionPoint))
            } catch (e: IOException) {
                return emptyList()
            }

            val urls = mutableListOf<String>()
            for (dp in distPoint.distributionPoints) {
                val dpn = dp.distributionPoint ?: continue
                if (dpn.type != DistributionPointName.FULL_NAME) continue
                val genNames = GeneralNames.getInstance(dpn.name).names
                for (gn in genNames) {
                    if (gn.tagNo == GeneralName.uniformResourceIdentifier) {
                        urls.add(DERIA5String.getInstance(gn.name).string)
                    }
                }
            }

            return urls.mapNotNull { createNewUrl(it, log) }
        }

    /**
     * Возвращает список OCSP-URL'ов, объявленных самим сертификатом в его
     * `authorityInfoAccess` extension'е (RFC 5280 §4.2.2.1, AccessMethod
     * `id-ad-ocsp` = 1.3.6.1.5.5.7.48.1).
     *
     * Это primary-источник для OCSP-проверки данного cert'а: cert сам говорит,
     * куда обращаться. Если AIA отсутствует или нет OCSP-записей, возвращается
     * пустой список, и вызывающий должен использовать fallback из конфига.
     */
    val ocspUrls: List<URL>
        get() {
            val aiaExt = x509Certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess.id)
                ?: return emptyList()

            return try {
                val aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(aiaExt))
                aia.accessDescriptions.asSequence()
                    .filter { AccessDescription.id_ad_ocsp == it.accessMethod }
                    .mapNotNull { ad ->
                        val gn = ad.accessLocation
                        if (gn.tagNo != GeneralName.uniformResourceIdentifier) null
                        else DERIA5String.getInstance(gn.name).string
                    }
                    .mapNotNull { createNewUrl(it, log) }
                    .toList()
            } catch (e: IOException) {
                log.warn("Failed to parse AuthorityInformationAccess extension", e)
                emptyList()
            }
        }

    /**
     * Валидация сертификата на указанную дату с учётом OCSP/CRL.
     */
    fun isValid(date: Date, checkOcsp: Boolean, checkCrl: Boolean): Boolean {
        if (!isDateValid(date)) return false
        val issuer = issuerCertificate ?: return false
        if (!issuer.isDateValid(date)) return false
        if (checkOcsp) {
            val statuses = ocspStatus ?: return false
            if (!statuses.all { it.isActive }) return false
        }
        if (checkCrl) {
            val status = crlStatus ?: return false
            if (status.result != CrlResult.ACTIVE) return false
        }
        return true
    }

    fun isDateValid(): Boolean = isDateValid(Date())

    fun isDateValid(date: Date): Boolean =
        // RFC 5280: период валидности — закрытый интервал [notBefore, notAfter].
        // notBefore == date и date == notAfter тоже считаются валидными.
        !date.before(x509Certificate.notBefore) && !date.after(x509Certificate.notAfter)

    val issuerX500Principal: X500Principal get() = x509Certificate.issuerX500Principal
    val subjectX500Principal: X500Principal get() = x509Certificate.subjectX500Principal

    fun verify(key: PublicKey): Boolean = try {
        x509Certificate.verify(key)
        true
    } catch (e: CertificateException) { false }
      catch (e: NoSuchAlgorithmException) { false }
      catch (e: SignatureException) { false }
      catch (e: InvalidKeyException) { false }
      catch (e: NoSuchProviderException) { false }

    val publicKey: PublicKey get() = x509Certificate.publicKey

    val extendedKeyUsage: List<String>
        get() = try {
            x509Certificate.extendedKeyUsage ?: emptyList()
        } catch (e: CertificateParsingException) {
            log.error("Certificate key user extracting error", e)
            emptyList()
        }

    private val keyUser: Set<CertificateKeyUser>
        get() = extendedKeyUsage.mapNotNull { CertificateKeyUser.fromOID(it).orElse(null) }.toSet()

    companion object {
        private val log = LoggerFactory.getLogger(CertificateWrapper::class.java)

        @JvmStatic
        fun fromBase64(encodedCert: String): CertificateWrapper? =
            fromBytes(Base64.getDecoder().decode(encodedCert.replace("\\s".toRegex(), "")))

        @JvmStatic
        fun fromBytes(encodedCert: ByteArray): CertificateWrapper? = try {
            ByteArrayInputStream(encodedCert).use { fromInputStream(it) }
        } catch (e: IOException) {
            null
        }

        @JvmStatic
        fun fromInputStream(inputStream: InputStream): CertificateWrapper? = try {
            val cert = CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                .generateCertificate(inputStream) as X509Certificate
            CertificateWrapper(cert)
        } catch (e: CertificateException) { null }
          catch (e: NoSuchProviderException) { null }

        @JvmStatic
        fun fromFile(file: File): CertificateWrapper? = try {
            fromInputStream(FileInputStream(file))
        } catch (e: FileNotFoundException) {
            null
        }

        private fun createCertificateSubjectFromDn(dn: String, fallbackEmail: String?): CertificateSubject? = try {
            val ldapName = LdapName(dn)
            var commonName: String? = null
            var lastName: String? = null
            var surName: String? = null
            var email: String? = null
            var organization: String? = null
            var iin: String? = null
            var bin: String? = null
            var country: String? = null
            var locality: String? = null
            var state: String? = null

            for (rdn in ldapName.rdns) {
                val type = rdn.type
                val value = rdn.value as? String ?: continue
                when {
                    type.equals("CN", ignoreCase = true) -> commonName = value
                    type.equals("SURNAME", ignoreCase = true) -> surName = value
                    type.equals("SERIALNUMBER", ignoreCase = true) -> {
                        if (value.startsWith("BIN")) bin = value.removePrefix("BIN")
                        else iin = value.removePrefix("IIN")
                    }
                    type.equals("C", ignoreCase = true) -> country = value
                    type.equals("L", ignoreCase = true) -> locality = value
                    type.equals("S", ignoreCase = true) -> state = value
                    type.equals("E", ignoreCase = true) || type.equals("EMAILADDRESS", ignoreCase = true) -> {
                        email = value
                    }
                    type.equals("O", ignoreCase = true) -> organization = value
                    type.equals("OU", ignoreCase = true) -> bin = value.removePrefix("BIN")
                    type.equals("G", ignoreCase = true) -> lastName = value
                }
            }

            // Современные NCA-сертификаты кладут email в SubjectAlternativeName
            // (rfc822Name), а не в Subject DN. Если в DN email не нашли,
            // подставляем из SAN, который пришёл сверху.
            CertificateSubject(
                commonName = commonName,
                lastName = lastName,
                surName = surName,
                email = email ?: fallbackEmail,
                organization = organization,
                iin = iin,
                bin = bin,
                country = country,
                locality = locality,
                state = state,
                dn = dn,
            )
        } catch (e: InvalidNameException) {
            log.warn("Distinguished name parsing error", e)
            null
        }

        /**
         * Извлекает email из SubjectAlternativeName extension'а
         * (RFC 5280 §4.2.1.6, GeneralName type 1 = rfc822Name).
         * Современные NCA-сертификаты публикуют email именно здесь, а не
         * в Subject DN.
         */
        private fun extractSanEmail(cert: X509Certificate): String? = try {
            cert.subjectAlternativeNames
                ?.firstOrNull { it.size >= 2 && it[0] == 1 && it[1] is String }
                ?.get(1) as? String
        } catch (e: CertificateParsingException) {
            log.warn("Failed to parse SubjectAlternativeName extension", e)
            null
        }
    }
}
