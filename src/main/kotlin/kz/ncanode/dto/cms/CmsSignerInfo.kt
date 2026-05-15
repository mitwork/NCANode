package kz.ncanode.dto.cms

import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.tsp.TspInfo

data class CmsSignerInfo(
    val certificates: List<CertificateInfo> = emptyList(),
    val tsp: TspInfo? = null,
)
