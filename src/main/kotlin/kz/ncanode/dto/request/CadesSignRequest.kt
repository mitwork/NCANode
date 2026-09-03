package kz.ncanode.dto.request

import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.tsp.TsaPolicy

/**
 * Запрос на подпись CAdES (ETSI EN 319 122-1).
 *
 * В отличие от `/cms/sign`, здесь нет отдельного флага `withTsp`: метка
 * времени — это уровень T, и уровень задаётся одним полем. Два способа
 * сказать одно и то же порождали бы вопрос, что делать при их конфликте.
 */
class CadesSignRequest {
    var data: String? = null

    /**
     * Готовый контейнер для доподписания (`PATCH /cades/sign`). Для подписи
     * с нуля не используется; для отсоединённой подписи вместе с ним нужен
     * [data] — содержимого в контейнере нет.
     */
    var cms: String? = null

    @NotEmpty
    var signers: List<@Valid SignerRequest> = emptyList()

    /** Требуемый уровень подписи. По умолчанию базовый. */
    var level: AdesLevel = AdesLevel.B

    /** Не вкладывать подписанные данные в CMS (detached). */
    var isDetached: Boolean = false

    /** Политика TSA; применяется начиная с уровня T. */
    var tsaPolicy: TsaPolicy? = null
}
