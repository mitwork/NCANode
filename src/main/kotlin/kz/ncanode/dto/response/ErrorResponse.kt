package kz.ncanode.dto.response

import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
class ErrorResponse(
    var details: String? = null,
) : StatusResponse()
