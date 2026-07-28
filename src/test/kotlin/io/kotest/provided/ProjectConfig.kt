package io.kotest.provided

import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension
import io.kotest.extensions.spring.SpringExtension

/**
 * Kotest 6 находит конфиг только по этому FQN (classpath-scanning удалён).
 *
 * SpringExtension обязан жить здесь, а не в телах спеков: constructor
 * injection (`@param:Autowired` в primary constructor) требует
 * ConstructorExtension ещё ДО инстанцирования спека — регистрация внутри
 * тела опаздывает и даёт SpecInstantiationException. На спеки без
 * Spring-аннотаций расширение не влияет.
 */
object ProjectConfig : AbstractProjectConfig() {
    override val extensions: List<Extension> = listOf(SpringExtension())
}
