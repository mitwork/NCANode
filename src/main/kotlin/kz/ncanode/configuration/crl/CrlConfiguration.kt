package kz.ncanode.configuration.crl

import java.net.URL

interface CrlConfiguration {
    val isEnabled: Boolean
    val isCacheEnabled: Boolean
    val isWarmupEnabled: Boolean
    val ttl: Int?
    val url: String?
    val urlList: Map<String, URL>
    val delta: CrlBaseConfiguration?
}
