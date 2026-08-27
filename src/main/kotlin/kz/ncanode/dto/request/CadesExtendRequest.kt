package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Повышение уровня готовой CAdES-подписи.
 *
 * Ключ для этого не нужен: уровни выше B ничего не подписывают заново, а
 * надстраиваются поверх — метка времени, данные об отзыве, архивная метка.
 * Отсюда основной сценарий: подписал клиент (например, в браузере через
 * NCALayer, которому доступны только B и T), а до LT/LTA документ доводит
 * сервер.
 */
class CadesExtendRequest {
    @NotEmpty
    var cms: String = ""

    /** Подписанные данные — для отсоединённой подписи. */
    var data: String? = null

    /** Требуемый уровень. Должен быть выше текущего. */
    var level: AdesLevel = AdesLevel.T

    /** Политика TSA; применяется к добавляемым меткам. */
    var tsaPolicy: TsaPolicy? = null
}
