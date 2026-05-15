plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    java
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

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
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
    // Spring Boot 3.x (jakarta namespace).
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    // AspectJ starter — нужен для @EnableCaching/@EnableRetry/@EnableScheduling/@EnableAsync;
    // тянет spring-aop, spring-aspects, aspectjweaver runtime.
    // В SB 4 переименован из spring-boot-starter-aop.
    implementation("org.springframework.boot:spring-boot-starter-aspectj")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    implementation("org.springframework.retry:spring-retry:2.0.10")
    // tomcat теперь приходит транзитивно через starter-web; war/providedRuntime убрали.

    // HTTP client. SB 3 поставляет httpclient5 в BOM, но наш код пока на 4.x API —
    // оставляем 4.5.x явной зависимостью (он совместим с jakarta-stack, т.к. не
    // касается servlet/web API напрямую).
    implementation("org.apache.httpcomponents:httpclient:4.5.14")

    // Lombok (используется в существующем Java-коде; убираем когда последний Java
    // файл будет портирован в Kotlin).
    compileOnly("org.projectlombok:lombok:1.18.40")
    annotationProcessor("org.projectlombok:lombok:1.18.40")

    // KalkanCrypt из flatDir lib/
    implementation(":knca_provider_jce_kalkan-0.7.5")
    implementation(":kalkancrypt-xmldsig-0.5")
    implementation("org.apache.santuario:xmlsec:4.0.3")

    // JWT GG2015
    implementation("kz.gov.pki:java-jwt:4.4.0")

    // SOAP/WSSE — jakarta-ery.
    // wss4j 4.0 тащит OpenSAML из Shibboleth-репо для SAML-token support;
    // NCANode только X.509 WSSE подписывает/проверяет, без SAML — exclude.
    implementation("org.apache.wss4j:wss4j-ws-security-dom:4.0.0") {
        exclude(group = "org.opensaml")
    }
    implementation("jakarta.xml.ws:jakarta.xml.ws-api:4.0.2")
    implementation("com.sun.xml.ws:jaxws-rt:4.0.3")

    // OpenAPI / Swagger UI — v2 (jakarta).
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.5.0")

    // PDFBox 3.x — jakarta-совместимый.
    implementation("org.apache.pdfbox:pdfbox:3.0.3")

    // BouncyCastle — bcprov-jdk18on (Java 17+ artifacts).
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.84")
}

springBoot {
    buildInfo()
}
