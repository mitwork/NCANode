package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

abstract class StatusResponse {
    var status: Int = HttpStatus.OK.value()
    var message: String? = "OK"
}
