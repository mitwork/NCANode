package kz.ncanode.dto.request

import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Повышение уровня готового PAdES-документа. Ключ не требуется — см.
 * [CadesExtendRequest].
 *
 * Доступны LT и LTA: они добавляются отдельными ревизиями файла. Уровень T
 * так добрать нельзя — метка времени подписи лежит внутри самой подписи, и
 * менять её содержимое после встраивания в PDF означало бы переподписать
 * документ.
 */
class PadesExtendRequest {
    @NotEmpty
    var pdf: String = ""

    /** Требуемый уровень: LT или LTA. */
    var level: AdesLevel = AdesLevel.LT

    /** Политика TSA; применяется к добавляемым меткам. */
    var tsaPolicy: TsaPolicy? = null
}
