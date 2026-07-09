package kz.ncanode.dto.certificate

import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
data class CertificateSubject(
    val commonName: String? = null,
    val lastName: String? = null,
    val surName: String? = null,
    val email: String? = null,
    val organization: String? = null,
    val iin: String? = null,
    val bin: String? = null,
    val country: String? = null,
    val locality: String? = null,
    val state: String? = null,
    val dn: String? = null,
)
