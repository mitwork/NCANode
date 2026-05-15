plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    java
    war
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
}

group = "kz"
version = (findProperty("version") as? String)
    ?.takeUnless { it.isBlank() || it == "unspecified" }
    ?: "4.0.0-SNAPSHOT"

// Java 25 через Gradle toolchain (auto-download через foojay resolver, см. settings.gradle.kts).
// Launcher JVM может оставаться на любом 17+ — Gradle сам подтянет JDK 25 для компиляции.
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
    // Spring
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    implementation("org.apache.httpcomponents:httpclient:4.5.13")
    implementation("org.springframework:spring-aspects:5.3.23")
    implementation("org.springframework.retry:spring-retry:1.3.3")
    providedRuntime("org.springframework.boot:spring-boot-starter-tomcat")

    // Lombok (используется в существующем Java-коде; убираем когда последний Java
    // файл будет портирован в Kotlin).
    compileOnly("org.projectlombok:lombok:1.18.40")
    annotationProcessor("org.projectlombok:lombok:1.18.40")

    // KalkanCrypt из flatDir lib/
    implementation(":knca_provider_jce_kalkan-0.7.5")
    implementation(":kalkancrypt-xmldsig-0.5")
    implementation("org.apache.santuario:xmlsec:3.0.3")

    // JWT GG2015
    implementation("kz.gov.pki:java-jwt:4.4.0")

    // SOAP/WSSE
    implementation("org.apache.ws.security:wss4j:1.6.19")
    implementation("org.apache.wss4j:wss4j-ws-security-dom:2.4.1")
    implementation("jakarta.xml.ws:jakarta.xml.ws-api:3.0.1")
    implementation("com.sun.xml.ws:jaxws-rt:3.0.2")
    implementation("org.springdoc:springdoc-openapi-ui:1.8.0")

    // PDFBox for PDF signing and verification
    implementation("org.apache.pdfbox:pdfbox:2.0.29")
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
}

// mainClass задан явно — иначе SB 2.7 plugin'овский ASM падает на Java 25 bytecode
// при сканировании @SpringBootApplication. Уйдёт при bump'е до SB 3+.
springBoot {
    mainClass = "kz.ncanode.NCANode"
    buildInfo()
}
