package kz.ncanode.wrapper

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.constants.MessageConstants
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.getAliases
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.io.IOException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.util.Base64

@Component
class KalkanWrapper(val kalkanProvider: KalkanProvider) {

    /**
     * Читает ключ P12.
     *
     * @param key Ключ в формате Base64
     * @param keyAlias Алиас ключа. Может быть null. Тогда выберется самый первый алиас в ключе.
     * @param password Пароль к ключу
     * @return Открытое хранилище ключей
     * @throws KeyException Если произошла ошибка при открытии ключа
     */
    @Throws(KeyException::class)
    fun read(key: String, keyAlias: String?, password: String): KeyStoreWrapper {
        val store = try {
            KeyStore.getInstance("PKCS12", kalkanProvider)
        } catch (e: KeyStoreException) {
            log.error(MessageConstants.KEY_ENGINE_ERROR, e)
            throw KeyException(MessageConstants.KEY_ENGINE_ERROR, e)
        }

        val decodedKey = try {
            Base64.getDecoder().decode(key)
        } catch (e: Exception) {
            log.error(MessageConstants.KEY_INVALID_BASE64, e)
            throw KeyException(MessageConstants.KEY_INVALID_BASE64, e)
        }

        try {
            decodedKey.inputStream().use { stream ->
                store.load(stream, password.toCharArray())
            }
        } catch (e: IOException) {
            val message = createMessageFromException(e)
            log.error(message, e)
            throw KeyException(message, e)
        } catch (e: NoSuchAlgorithmException) {
            val message = createMessageFromException(e)
            log.error(message, e)
            throw KeyException(message, e)
        } catch (e: CertificateException) {
            val message = createMessageFromException(e)
            log.error(message, e)
            throw KeyException(message, e)
        }

        val aliases = getAliases(store)
        if (aliases.isEmpty()) {
            log.error(MessageConstants.KEY_ALIASES_NOT_FOUND)
            throw KeyException(MessageConstants.KEY_ALIASES_NOT_FOUND)
        }

        val resolvedAlias = if (keyAlias != null) {
            if (keyAlias !in aliases) {
                val err = String.format(MessageConstants.KEY_ALIAS_NOT_FOUND, keyAlias)
                log.error(err)
                throw KeyException(err)
            }
            // явный alias валидный — используем именно его, а не первый из списка
            keyAlias
        } else {
            aliases[0]
        }

        return KeyStoreWrapper(store, resolvedAlias, password, aliases)
    }

    /**
     * Читает ключи из запроса SignerRequest.
     */
    fun read(signers: List<SignerRequest>): List<KeyStoreWrapper> =
        signers.mapIndexed { index, request -> tryReadKey(request, index) }

    /**
     * Пытается прочитать ключ. Если ничего не получилось, оборачивает в
     * ServerException с индексом подписанта.
     */
    private fun tryReadKey(request: SignerRequest, index: Int): KeyStoreWrapper = try {
        read(request.key, request.keyAlias, request.password)
    } catch (e: KeyException) {
        val errorMessage = "signers[$index]: ${e.message}"
        log.error(errorMessage, e.cause)
        throw ServerException(errorMessage, e.cause)
    }

    /**
     * Преобразует текст ошибки из KalkanCrypt в наш короткий код. Сделано,
     * чтобы в ответ сервера не попадали внутренние детали реализации.
     */
    private fun createMessageFromException(e: Exception): String = when (e.message) {
        "stream does not represent a PKCS12 key store" -> MessageConstants.KEY_INVALID_FORMAT
        "PKCS12 key store mac invalid - wrong password or corrupted file." -> MessageConstants.KEY_INVALID_PASSWORD
        else -> MessageConstants.KEY_UNKNOWN_ERROR
    }

    companion object {
        private val log = LoggerFactory.getLogger(KalkanWrapper::class.java)
    }
}
