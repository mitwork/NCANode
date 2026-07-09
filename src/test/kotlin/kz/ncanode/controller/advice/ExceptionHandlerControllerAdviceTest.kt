package kz.ncanode.controller.advice

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kz.ncanode.configuration.SystemConfiguration
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException

/**
 * Покрытие ExceptionHandlerControllerAdvice без поднятия Spring MVC
 * (routing самих Spring-исключений — в ExceptionHandlingMvcTest).
 *
 * Контракт:
 *  - ApplicationException → status из подкласса (400/404/500), message как есть
 *    (мы его сами формируем, утечки нет);
 *  - непредвиденный RuntimeException → 500, но БЕЗ утечки: message обобщён
 *    ("Internal server error") пока не включён detailedErrors;
 *  - details — только при isDetailedErrors=true И наличии cause.
 */
class ExceptionHandlerControllerAdviceTest : FunSpec({

    test("ClientException maps to 400 with message preserved") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val resp = advice.handleApplicationException(ClientException("bad request body"))

        resp.statusCode.value() shouldBe 400
        resp.body!!.status shouldBe 400
        resp.body!!.message shouldBe "bad request body"
    }

    test("ServerException maps to 500 with message preserved") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val resp = advice.handleApplicationException(ServerException("crl loader failed"))

        resp.statusCode.value() shouldBe 500
        resp.body!!.message shouldBe "crl loader failed"
    }

    test("unexpected RuntimeException maps to 500 with GENERIC message (no internal leak)") {
        // detailedErrors=false по умолчанию: клиенту не уходит внутренний текст
        // (helpful-NPE с именами полей, пути парсера и т.п.).
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val resp = advice.handleUnexpected(RuntimeException("cannot invoke kz.ncanode.Internal.x because y is null"))

        resp.statusCode.value() shouldBe 500
        resp.body!!.status shouldBe 500
        resp.body!!.message shouldBe "Internal server error"
        resp.body!!.details.shouldBeNull()
    }

    test("unexpected RuntimeException exposes real message when detailedErrors=true") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration().apply { isDetailedErrors = true })

        val resp = advice.handleUnexpected(RuntimeException("boom"))

        resp.body!!.message shouldBe "boom"
    }

    test("details exposed only when isDetailedErrors=true AND cause is present") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration().apply { isDetailedErrors = true })

        val cause = IllegalStateException("inner cause: file not found")
        val resp = advice.handleApplicationException(ServerException("crl loader failed", cause))

        resp.body!!.details shouldBe "inner cause: file not found"
    }

    test("details NOT exposed when isDetailedErrors=false even if cause present") {
        val advice = ExceptionHandlerControllerAdvice(SystemConfiguration())

        val cause = IllegalStateException("secret-ish internal message")
        val resp = advice.handleApplicationException(ServerException("public msg", cause))

        resp.body!!.details.shouldBeNull()
    }
})
