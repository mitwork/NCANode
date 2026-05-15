package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.tsp.TsaPolicy

class CmsCreateRequest {
    var cms: String? = null
    var data: String? = null

    @NotEmpty
    var signers: List<SignerRequest> = emptyList()

    var isWithTsp: Boolean = false
    var tsaPolicy: TsaPolicy? = null
    var isDetached: Boolean = false
}
