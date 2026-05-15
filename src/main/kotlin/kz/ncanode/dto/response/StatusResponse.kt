package kz.ncanode.dto.response

import com.fasterxml.jackson.annotation.JsonPropertyOrder
import org.springframework.http.HttpStatus

/**
 * `status` и `message` ставим в верх JSON-ответа — так было в Lombok-эпохе
 * (`@SuperBuilder` сериализовал родительские поля первыми). Остальные поля
 * каждого подкласса идут после в их объявленном порядке.
 */
@JsonPropertyOrder("status", "message")
abstract class StatusResponse(
    var status: Int = HttpStatus.OK.value(),
    var message: String? = "OK",
)
