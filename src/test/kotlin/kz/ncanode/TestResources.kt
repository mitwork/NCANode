package kz.ncanode

import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import java.security.Security
import java.util.Base64

/**
 * Общие хелперы для unit/integration-тестов.
 *
 * Подгружает KalkanProvider один раз на JVM (через `init`-блок объекта,
 * Kotlin гарантирует thread-safe initialization при первом обращении) —
 * Spring contexts тестам тут не нужен.
 */
object TestResources {

    init {
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) {
            Security.addProvider(KalkanProvider())
        }
    }

    /**
     * Регистрирует KalkanProvider — достаточно обратиться к объекту, но вызов
     * читается как намерение, а не как случайная строка в спеке.
     */
    fun bootstrap() = Unit

    /**
     * Читает test-resource как Base64-encoded строку. Возвращаемое значение
     * — то, что обычно прилетает в API-запросе `key: "..."`.
     */
    fun loadAsBase64(path: String): String {
        val bytes = javaClass.classLoader.getResourceAsStream(path)?.use { it.readBytes() }
            ?: error("Test resource not found: $path")
        return Base64.getEncoder().encodeToString(bytes)
    }

    /** Сырое содержимое test-resource как `ByteArray`. */
    fun loadBytes(path: String): ByteArray {
        return javaClass.classLoader.getResourceAsStream(path)?.use { it.readBytes() }
            ?: error("Test resource not found: $path")
    }

    /** Пароль ко всем p12 из NCA SDK 2.0 test pack. */
    const val P12_PASSWORD = "Qwerty12"
}
