package kz.ncanode.controller.advice

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.mockk.mockk
import kz.ncanode.configuration.SystemConfiguration
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException

/**
 * Покрытие ExceptionHandlerControllerAdvice без поднятия Spring MVC.
 *
 * Контракт:
 *  - plain RuntimeException → 500 (никакой утечки stack-trace, message — как есть),
 *  - ApplicationException → специфичный status из подкласса (400/500/...),
 *  - details выставляются только при isDetailedErrors=true И наличии cause.
 *
 * Это безопасный default — без isDetailedErrors клиенту не уходит
 * деталь внутренней ошибки (e.g. SQL/stacktrace), которая может раскрыть
 * структуру приложения.
 */
class ExceptionHandlerControllerAdviceTest : FunSpec({

    test("plain RuntimeException maps to 500 with message preserved") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())  // detailedErrors=false по умолчанию

        val resp = advice.handleRuntimeException(RuntimeException("boom"), mockk(relaxed = true))

        resp.statusCode.value() shouldBe 500
        resp.body!!.status shouldBe 500
        resp.body!!.message shouldBe "boom"
        resp.body!!.details.shouldBeNull()
    }

    test("ClientException maps to 400 (status from the exception class)") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val resp = advice.handleRuntimeException(ClientException("bad request body"), mockk(relaxed = true))

        resp.statusCode.value() shouldBe 400
        resp.body!!.status shouldBe 400
        resp.body!!.message shouldBe "bad request body"
    }

    test("ServerException maps to 500") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val resp = advice.handleRuntimeException(ServerException("crl loader failed"), mockk(relaxed = true))

        resp.statusCode.value() shouldBe 500
        resp.body!!.message shouldBe "crl loader failed"
    }

    test("details exposed only when isDetailedErrors=true AND cause is present") {
        val sysCfg = SystemConfiguration().apply { isDetailedErrors = true }
        val advice = ExceptionHandlerControllerAdvice(sysCfg)

        val cause = IllegalStateException("inner cause: file not found")
        val resp = advice.handleRuntimeException(ServerException("crl loader failed", cause), mockk(relaxed = true))

        resp.body!!.details shouldBe "inner cause: file not found"
    }

    test("details NOT exposed when isDetailedErrors=false even if cause present") {
        // Дефолтный безопасный режим: не утекаем внутренние сообщения в API.
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val cause = IllegalStateException("secret-ish internal message")
        val resp = advice.handleRuntimeException(ServerException("public msg", cause), mockk(relaxed = true))

        resp.body!!.details.shouldBeNull()
    }

    test("details=null even with isDetailedErrors=true when no cause") {
        val sysCfg = SystemConfiguration().apply { isDetailedErrors = true }
        val advice = ExceptionHandlerControllerAdvice(sysCfg)

        val resp = advice.handleRuntimeException(ServerException("no cause attached"), mockk(relaxed = true))

        resp.body!!.details.shouldBeNull()
    }
})
