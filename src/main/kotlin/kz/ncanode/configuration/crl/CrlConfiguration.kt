package kz.ncanode.configuration.crl

import java.net.URL

interface CrlConfiguration {
    val isEnabled: Boolean
    val isCacheEnabled: Boolean
    val isWarmupEnabled: Boolean

    /**
     * Strict-режим (SSRF-защита). Если true — on-demand загрузка CRL из
     * cRLDistributionPoints сертификата ОТКЛЮЧЕНА; используются только
     * scheduled конфиг-CRL. Серт злоумышленника не может заставить сервер
     * скачать CRL с произвольного (внутреннего) URL. Default false.
     */
    val isStrict: Boolean

    val ttl: Int?
    val url: String?
    val urlList: Map<String, URL>
    val delta: CrlBaseConfiguration?
}
