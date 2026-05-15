package kz.ncanode.wrapper

import kz.ncanode.constants.MessageConstants
import kz.ncanode.exception.ServerException
import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.X509Certificate

class KeyStoreWrapper(
    val keyStore: KeyStore,
    val alias: String,
    val password: String,
    val aliases: List<String>,
) {
    /**
     * Извлекает приватный ключ.
     */
    val privateKey: PrivateKey
        get() = try {
            keyStore.getKey(alias, password.toCharArray()) as PrivateKey
        } catch (e: KeyStoreException) {
            log.error(MessageConstants.KEY_CANT_EXTRACT_PRIVATE_KEY, e)
            throw ServerException(MessageConstants.KEY_CANT_EXTRACT_PRIVATE_KEY, e)
        } catch (e: NoSuchAlgorithmException) {
            log.error(MessageConstants.KEY_CANT_EXTRACT_PRIVATE_KEY, e)
            throw ServerException(MessageConstants.KEY_CANT_EXTRACT_PRIVATE_KEY, e)
        } catch (e: UnrecoverableKeyException) {
            log.error(MessageConstants.KEY_CANT_EXTRACT_PRIVATE_KEY, e)
            throw ServerException(MessageConstants.KEY_CANT_EXTRACT_PRIVATE_KEY, e)
        }

    /**
     * Извлекает сертификат из Signer.
     */
    val certificate: CertificateWrapper
        get() = try {
            CertificateWrapper(keyStore.getCertificate(alias) as X509Certificate)
        } catch (e: KeyStoreException) {
            log.error(MessageConstants.KEY_CANT_EXTRACT_CERTIFICATE, e)
            throw ServerException(MessageConstants.KEY_CANT_EXTRACT_CERTIFICATE, e)
        }

    companion object {
        private val log = LoggerFactory.getLogger(KeyStoreWrapper::class.java)
    }
}
