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

    /**
     * Потолок размера скачиваемого CRL в мегабайтах. Загрузка обрывается, как
     * только тело ответа его превысило (а если сервер прислал Content-Length —
     * ещё до чтения тела). Ноль или меньше — без ограничения.
     *
     * Нужен потому, что в нестрогом режиме URL берётся из
     * `cRLDistributionPoints` присланного сертификата: без потолка такой
     * сертификат заставляет сервер скачать файл произвольного размера.
     */
    val maxSizeMb: Int

    /**
     * Максимум CRL-файлов в on-demand кэше (тех, что скачаны по CRL DP из
     * сертификата). При превышении вытесняются реже всего использованные —
     * вместе с их файлами-спутниками. Ноль или меньше — без ограничения.
     */
    val onDemandMaxEntries: Int

    val ttl: Int?
    val url: String?
    val urlList: Map<String, URL>
    val delta: CrlBaseConfiguration?
}
