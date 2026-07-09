package kz.ncanode.dto.request

import com.fasterxml.jackson.annotation.JsonIgnore
import kz.ncanode.dto.certificate.CertificateRevocation

abstract class VerifyRequest {
    var revocationCheck: Set<CertificateRevocation> = emptySet()

    /**
     * Расшифровка `revocationCheck` в булевы флаги. Раньше проверка «OCSP/CRL в
     * наборе» была размазана по контроллерам и сервисам (~двумя дюжинами
     * вхождений). `@JsonIgnore` — это вычисляемое поле, оно не должно попадать
     * в JSON-схему/десериализацию.
     */
    @get:JsonIgnore
    val checkOcsp: Boolean get() = CertificateRevocation.OCSP in revocationCheck

    @get:JsonIgnore
    val checkCrl: Boolean get() = CertificateRevocation.CRL in revocationCheck
}
