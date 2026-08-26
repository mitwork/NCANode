package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/** Ответ batch-проверки XAdES: на каждый XML — свой полный результат. */
class XadesVerificationBatchResponse(
    var results: List<XadesVerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
