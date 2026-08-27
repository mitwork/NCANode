package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Batch-вариант [CadesSignRequest]: подписывает массив данных одним и тем же
 * набором signer'ов до одного уровня (issue malikzh/NCANode#212).
 *
 * Уровень общий на весь batch намеренно: смешивать в одном запросе B и LTA
 * незачем, а разный уровень на элемент сделал бы неоднозначным, что означает
 * частичный отказ на уровне LT.
 */
class CadesSignBatchRequest {
    @NotEmpty
    var data: List<String> = emptyList()

    @NotEmpty
    var signers: List<@Valid SignerRequest> = emptyList()

    /** Требуемый уровень подписи. По умолчанию базовый. */
    var level: AdesLevel = AdesLevel.B

    /** Не вкладывать подписанные данные в CMS (detached). */
    var isDetached: Boolean = false

    /** Политика TSA; применяется начиная с уровня T. */
    var tsaPolicy: TsaPolicy? = null
}
