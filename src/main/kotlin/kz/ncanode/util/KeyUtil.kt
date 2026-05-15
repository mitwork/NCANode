@file:JvmName("KeyUtil")

package kz.ncanode.util

import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.security.KeyStoreException

private val log = LoggerFactory.getLogger("kz.ncanode.util.KeyUtil")

/**
 * Преобразует алиасы в список.
 */
fun getAliases(key: KeyStore): List<String> = try {
    key.aliases().toList()
} catch (e: KeyStoreException) {
    log.warn("Could not enumerate keystore aliases", e)
    emptyList()
}
