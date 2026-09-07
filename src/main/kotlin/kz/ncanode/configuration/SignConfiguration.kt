package kz.ncanode.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

/**
 * Политика подписания (`ncanode.sign.*`).
 */
@Configuration
@ConfigurationProperties(prefix = "ncanode.sign")
open class SignConfiguration {

    /**
     * Проверять сертификат подписанта ПЕРЕД формированием подписи —
     * п. 4 Правил формирования и проверки подлинности ЭЦП (приказ МИИ РК
     * №500/НҚ): подпись УЦ, срок действия, отсутствие отзыва (OCSP, при его
     * недоступности — CRL) и допустимость назначения ключа.
     *
     * Выключено по умолчанию: включение меняет поведение всех sign-эндпойнтов
     * (просроченный или отозванный ключ начинает получать отказ 400 вместо
     * подписи) и добавляет обращение к OCSP на каждое подписание. Развёртывание,
     * которое обязано соответствовать Правилам, включает это флагом
     * `NCANODE_SIGN_CERT_CHECK=true`; проверка выполняется теми же средствами,
     * что и верификация, поэтому её вердикт совпадает с тем, что потом скажет
     * `/{cms,xml,pdf}/verify`.
     */
    var isCertificateCheck: Boolean = false
}
