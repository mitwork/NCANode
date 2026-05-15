package kz.ncanode.constants

object MessageConstants {
    // KeyService
    const val KEY_INVALID_BASE64 = "Key reading error: Invalid Base64 format. Key must be in valid Base64 format."
    const val KEY_INVALID_FORMAT = "Key reading error: Invalid format."
    const val KEY_INVALID_PASSWORD = "Key reading error: Password incorrect."
    const val KEY_UNKNOWN_ERROR = "Key reading error: Unknown error. Please see logs."
    const val KEY_ENGINE_ERROR = "Key reading error: Engine error. Please see logs."
    const val KEY_ALIASES_NOT_FOUND = "Key reading error: Key does not have aliases."
    const val KEY_ALIAS_NOT_FOUND = "Key reading error: Key does not have '%s' alias"
    const val KEY_CANT_EXTRACT_PRIVATE_KEY = "Key reading error: Cannot extract private key."
    const val KEY_CANT_EXTRACT_CERTIFICATE = "Key reading error: Cannot extract certificate."
    const val CERT_INVALID = "[%d]: Invalid certificate given."
}
