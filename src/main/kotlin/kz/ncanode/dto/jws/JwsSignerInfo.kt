package kz.ncanode.dto.jws

import kz.ncanode.dto.certificate.CertificateInfo

/**
 * Сведения об одной подписи JWS.
 *
 * [header] — разобранный protected-заголовок: он подписан, и клиенту важно
 * видеть именно то, что покрыто подписью, а не то, что мы о нём думаем.
 */
data class JwsSignerInfo(
    val valid: Boolean = false,
    val header: Map<String, Any?> = emptyMap(),
    val certificate: CertificateInfo? = null,
)
