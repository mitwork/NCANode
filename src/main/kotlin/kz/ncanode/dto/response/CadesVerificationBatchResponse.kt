package kz.ncanode.dto.response

import org.springframework.http.HttpStatus

/**
 * Ответ batch-проверки CAdES. Каждый элемент — полноценный
 * [CadesVerificationResponse]. Агрегированный `valid` намеренно не
 * публикуется: клиент сам решает, сводить ли результаты в AND.
 */
class CadesVerificationBatchResponse(
    var results: List<CadesVerificationResponse> = emptyList(),
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
