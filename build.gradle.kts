import java.net.HttpURLConnection
import java.net.URI
import java.util.concurrent.TimeUnit

plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    java
    jacoco
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
}

group = "kz"
version = (findProperty("version") as? String)
    ?.takeUnless { it.isBlank() || it == "unspecified" }
    ?: "4.0.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

kotlin {
    jvmToolchain(25)
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

repositories {
    flatDir { dirs("lib") }
    mavenLocal()
    mavenCentral()
    maven { url = uri("https://pkgs.dev.azure.com/as1an/public/_packaging/repo/maven/v1") }
}

tasks.bootJar { duplicatesStrategy = DuplicatesStrategy.EXCLUDE }
tasks.jar { duplicatesStrategy = DuplicatesStrategy.EXCLUDE }

dependencies {
    // Spring Boot 4.x (jakarta namespace).
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // Prometheus scrape endpoint (/actuator/prometheus). Версия из SB BOM.
    implementation("io.micrometer:micrometer-registry-prometheus")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    // AspectJ starter — нужен для AOP-прокси @Async / @Scheduled
    // (spring-aop + spring-aspects + aspectjweaver runtime).
    implementation("org.springframework.boot:spring-boot-starter-aspectj")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    // tomcat теперь приходит транзитивно через starter-web; war/providedRuntime убрали.

    // KalkanCrypt из flatDir lib/
    implementation(":knca_provider_jce_kalkan-0.7.8")
    implementation(":kalkancrypt-xmldsig-0.5")
    implementation("org.apache.santuario:xmlsec:4.0.4")

    // JWT GG2015
    implementation("kz.gov.pki:java-jwt:4.4.0")

    // SOAP/WSSE — jakarta-ery.
    // wss4j 4.0 тащит OpenSAML из Shibboleth-репо для SAML-token support;
    // NCANode только X.509 WSSE подписывает/проверяет, без SAML — exclude.
    implementation("org.apache.wss4j:wss4j-ws-security-dom:4.0.1") {
        exclude(group = "org.opensaml")
    }
    // SAAJ runtime — даёт jakarta.xml.soap.MessageFactory, который использует
    // WsseService для парсинга/перепаковки SOAP envelope'ов. wss4j подтягивает
    // только jakarta.xml.soap-api (интерфейсы), реализацию нужно дать явно.
    implementation("com.sun.xml.ws:jaxws-rt:4.0.5")

    // OpenAPI / Swagger UI — v3 (для Spring 7 / SB 4).
    // springdoc 2.x ссылается на удалённый в Spring 7 конструктор
    // ControllerAdviceBean(Object) — NoSuchMethodError на любой запрос
    // через DispatcherServlet с @ControllerAdvice бином.
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:3.1.0")

    // PDFBox 3.x — jakarta-совместимый.
    implementation("org.apache.pdfbox:pdfbox:3.0.8")

    // BouncyCastle — bcprov-jdk18on (Java 17+ artifacts).
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.85")

    // Тесты — Kotest (JUnit 5 runner) + MockK + Spring Boot Test.
    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation(libs.bundles.kotest)
    testImplementation(libs.kotest.spring)
    testImplementation(libs.mockk)
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }
    classDirectories.setFrom(
        files(classDirectories.files.map {
            fileTree(it).apply {
                // Шум для покрытия: DTO data classes, ENUM-объекты, Spring boilerplate,
                // main-точка. Хочется видеть покрытие сервисов / wrapper'ов / util'ов.
                exclude(
                    "kz/ncanode/NCANode*",
                    "kz/ncanode/NCANode\$OpenApiConfig*",
                    "kz/ncanode/constants/**",
                    "kz/ncanode/dto/**",
                    "kz/ncanode/exception/**",
                    "kz/ncanode/configuration/**",
                    "kz/ncanode/oid/**",
                )
            }
        })
    )
}

springBoot {
    buildInfo()
}

/**
 * Live-генерация openapi.yml.
 *
 * `./gradlew generateOpenApiDocs` поднимает приложение через bootJar
 * на временном порту 14580 (не пересекаемся с дефолтным 14579),
 * забирает spec через /v3/api-docs.yaml и сохраняет в корень репо
 * как openapi.yml. После — глушит процесс.
 *
 * Файл публикуется через .github/workflows/github-pages.yml как
 * статичный Swagger UI на GitHub Pages. После каждого изменения API
 * (новый endpoint, переименование тэга и т.д.) нужно перегенерировать
 * и закоммитить.
 *
 * Реализация ручная (не через springdoc-openapi-gradle-plugin) —
 * плагин не пробрасывает Java toolchain в форкнутый процесс,
 * поэтому стартует Java 17 на классах Java 25 → UnsupportedClassVersionError.
 */
tasks.register("generateOpenApiDocs") {
    group = "openapi"
    description = "Boot the app, fetch /v3/api-docs.yaml, save as openapi.yml"
    dependsOn(tasks.bootJar)

    doLast {
        val javaExe = javaToolchains.launcherFor {
            languageVersion.set(JavaLanguageVersion.of(25))
        }.get().executablePath.asFile.absolutePath
        val jar = tasks.bootJar.get().archiveFile.get().asFile
        val port = 14580
        val specUrl = URI("http://localhost:$port/v3/api-docs.yaml").toURL()
        val outputFile = layout.projectDirectory.file("openapi.yml").asFile

        val process = ProcessBuilder(
            javaExe, "-jar", jar.absolutePath, "--server.port=$port",
        ).redirectErrorStream(true).start()

        try {
            // Poll до 90 секунд (CA bundle download при первом старте может занять до минуты).
            val deadline = System.currentTimeMillis() + 90_000
            var lastErr: Exception? = null
            while (System.currentTimeMillis() < deadline) {
                if (!process.isAlive) {
                    error("Application process died unexpectedly before serving spec")
                }
                try {
                    val conn = specUrl.openConnection() as HttpURLConnection
                    conn.connectTimeout = 1000
                    conn.readTimeout = 5000
                    if (conn.responseCode == 200) {
                        val yaml = conn.inputStream.bufferedReader().use { it.readText() }
                        outputFile.writeText(yaml)
                        logger.lifecycle("openapi.yml updated (${yaml.length} bytes) ← $specUrl")
                        return@doLast
                    }
                    conn.disconnect()
                } catch (e: Exception) {
                    lastErr = e
                }
                Thread.sleep(1000)
            }
            error("Failed to fetch $specUrl within 90s (last error: ${lastErr?.message})")
        } finally {
            process.destroy()
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly()
            }
        }
    }
}
