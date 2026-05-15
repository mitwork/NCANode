package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull
import com.fasterxml.jackson.annotation.JsonAnyGetter
import com.fasterxml.jackson.annotation.JsonAnySetter

class JwtEncodeRequest {
    @NotNull
    @Valid
    lateinit var jwt: JwtRequest

    @NotEmpty
    var key: String = ""

    @NotEmpty
    var password: String = ""

    var keyAlias: String? = null

    class JwtRequest {
        @NotNull
        @Valid
        lateinit var header: JwtHeader

        @NotNull
        @Valid
        lateinit var payload: JwtPayload
    }

    class JwtHeader {
        @NotEmpty
        var alg: String = ""

        @NotEmpty
        var typ: String = ""
    }

    class JwtPayload {
        @get:JsonAnyGetter
        val claims: MutableMap<String, Any?> = LinkedHashMap()

        @JsonAnySetter
        fun setClaim(key: String, value: Any?) {
            claims[key] = value
        }
    }
}
