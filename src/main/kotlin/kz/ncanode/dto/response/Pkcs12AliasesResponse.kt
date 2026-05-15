package kz.ncanode.dto.response

class Pkcs12AliasesResponse(
    var aliases: List<List<String>> = emptyList(),
) : StatusResponse()
