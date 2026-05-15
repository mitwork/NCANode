package kz.ncanode.dto.tsp

import java.util.Date

data class TspInfo(
    val serialNumber: String? = null,
    val genTime: Date? = null,
    val policy: String? = null,
    val tsa: String? = null,
    val tspHashAlgorithm: String? = null,
    val hash: String? = null,
)
