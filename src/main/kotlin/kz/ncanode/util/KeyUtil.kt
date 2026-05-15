package kz.ncanode.util

import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.security.KeyStoreException

object KeyUtil {

    private val log = LoggerFactory.getLogger(KeyUtil::class.java)

    /**
     * Преобразует алиасы в список.
     */
    @JvmStatic
    fun getAliases(key: KeyStore): List<String> = try {
        key.aliases().toList()
    } catch (e: KeyStoreException) {
        log.warn("Could not enumerate keystore aliases", e)
        emptyList()
    }
}
