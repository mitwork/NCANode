package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.tsp.TsaPolicy

class PdfSignRequest {
    @NotEmpty
    var pdf: String = ""

    @NotEmpty
    var signers: List<PdfSigner> = emptyList()

    var isWithTsp: Boolean = false

    var tsaPolicy: TsaPolicy? = null

    class PdfSigner {
        var reason: String? = null
        var location: String? = null
        var contactInfo: String? = null

        @NotEmpty
        lateinit var signer: SignerRequest
    }
}
