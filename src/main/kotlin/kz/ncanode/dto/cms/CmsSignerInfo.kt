package kz.ncanode.dto.cms

import kz.ncanode.dto.certificate.CertificateInfo
import kz.ncanode.dto.tsp.TspInfo

data class CmsSignerInfo(
    /**
     * Вердикт по этому подписанту. Раньше наружу отдавался только общий флаг
     * по документу, и в многоподписном CMS нельзя было понять, кто именно не
     * прошёл проверку.
     */
    val valid: Boolean = false,
    val certificates: List<CertificateInfo> = emptyList(),
    val tsp: TspInfo? = null,
)
