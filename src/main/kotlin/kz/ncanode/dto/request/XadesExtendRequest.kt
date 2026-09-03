package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Повышение уровня готовой XAdES-подписи. Ключ не требуется — см.
 * [CadesExtendRequest].
 *
 * Поднимаются все подписи документа: уровень документа определяется слабейшей
 * из них, и повышать их выборочно смысла нет.
 */
class XadesExtendRequest {
    @NotEmpty
    var xml: String = ""

    /** Требуемый уровень. Должен быть выше текущего. */
    var level: AdesLevel = AdesLevel.T

    /** Политика TSA; применяется к добавляемым меткам. */
    var tsaPolicy: TsaPolicy? = null
}
