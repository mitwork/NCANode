package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/** Ответ batch-проверки PAdES: на каждый PDF — свой полный результат. */
class PadesVerificationBatchResponse(
    var results: List<PadesVerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
