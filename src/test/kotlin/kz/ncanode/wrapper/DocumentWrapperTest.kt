package kz.ncanode.wrapper

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kz.ncanode.exception.ServerException

class DocumentWrapperTest : FunSpec({

    test("parses valid XML and exposes documentElement") {
        val doc = DocumentWrapper("""<root><child>value</child></root>""")
        doc.documentElement.tagName shouldBe "root"
    }

    test("invalid XML throws ServerException") {
        val ex = try {
            DocumentWrapper("not <valid xml<")
            null
        } catch (e: ServerException) {
            e
        }
        ex.shouldNotBeNull()
        ex.message shouldContain "Cannot read XML"
    }

    test("XXE: external entity is NOT resolved during parsing") {
        // OWASP: внешние сущности должны игнорироваться.
        // Если parser резолвит example.com — это утечка инфы по сети.
        // Если читает /etc/passwd через file:// — это уже SSRF/file disclosure.
        // Мы передаём external entity, но parser сконфигурен не дёргать его.
        val malicious = """<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <root>&xxe;</root>""".trimIndent()
        // Парсинг проходит (DOCTYPE не запрещён — нужен для legit XMLDSIG),
        // но &xxe; не должен раскрыться в содержимое /etc/passwd.
        val doc = DocumentWrapper(malicious)
        val text = doc.toString()
        text.shouldNotContain("root:")  // признак содержимого /etc/passwd
        text.shouldNotContain("/bin/bash")
    }

    test("toString roundtrip preserves XML content") {
        val original = """<root><a>1</a><b>2</b></root>"""
        val doc = DocumentWrapper(original)
        val rendered = doc.toString()
        // Сериализация может добавить XML declaration, но контент — тот же.
        rendered shouldContain "<a>1</a>"
        rendered shouldContain "<b>2</b>"
    }
})
