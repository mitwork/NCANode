package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

class Pkcs12AliasesResponse(
    var aliases: List<List<String>> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
