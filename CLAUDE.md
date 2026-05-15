# CLAUDE.md — onboarding context for NCANode v4

Этот файл — контекст для возобновления работы (в т.ч. с другого
компьютера). Содержит: что сделано, где что лежит, чем продолжать.

## TL;DR

- **Текущая ветка:** `v4`. Это полная переписка NCANode с Java/Spring Boot
  2.7 + Lombok на 100% Kotlin / Spring Boot 4.0 / Java 25 / Gradle 9.
- **Параллельная ветка:** `improvements` — Java версия с теми же
  improvements'ами (CRL cache, OCSP parallel, CAdES-T fixes, request log,
  health indicator). Сохранена для возможности PR'а в upstream
  malikzh/NCANode. v4 в upstream не пойдёт (другой язык).
- **Состояние v4:** functional + 84 теста / 70% coverage. Готова к
  CI/CD-фазе, или к продолжению расширения покрытия.

## Стек

| | |
|---|---|
| **JVM** | Java 25 (toolchain через foojay-resolver) |
| **Kotlin** | 2.3.21 |
| **Spring Boot** | 4.0.6 |
| **Spring Framework** | 7 (через SB 4 BOM) |
| **Gradle** | 9.5.1 |
| **Jakarta EE** | jakarta.* (НЕ javax.* кроме JDK-native xml/naming/security.auth) |
| **Jackson** | 3 (tools.jackson.*) через jackson-module-kotlin — без Jackson 2 fallback'а |
| **Кriptoprovider** | Kalkan 0.7.5 + kalkancrypt-xmldsig 0.5 (flatDir `lib/`) |
| **TLS/PKI deps** | BouncyCastle bcprov/bcpkix-jdk18on 1.84, Santuario xmlsec 4.0.3, wss4j 4.0.0 (без OpenSAML), pdfbox 3.0.3, jaxws-rt 4.0.3, springdoc 3.0.3 |
| **HTTP client** | Apache httpclient 4.5.14 (4.x API — не 5.x) |
| **Тесты** | Kotest 5.9 (JUnit 5 runner) + MockK 1.14 + spring-boot-starter-test |

Build clean (zero warnings). `./gradlew bootJar` зелёный.

## Архитектура — single module

```
src/main/kotlin/kz/ncanode/
  NCANode.kt                  ← @SpringBootApplication + main + banner
  configuration/              ← @Configuration beans + RequestLoggingFilter
    crl/                      ← CrlConfiguration interface + 2 наследника
  constants/MessageConstants  ← object с const val (error message keys)
  controller/                 ← 8 @RestController + advice/
  dto/
    certificate/, cms/, crl/, http/, ocsp/, pdf/, request/, response/, tsp/
  exception/                  ← 8 классов, ApplicationException base
  oid/                        ← NcaOids, NcaAlgorithms, KnownEkus (импортировано из demo-pki-center)
  service/                    ← 15 @Service
  util/                       ← Util, KalkanUtil, KeyUtil (top-level functions, @file:JvmName)
  wrapper/                    ← CertificateWrapper, KeyStoreWrapper, KalkanWrapper, DocumentWrapper, XMLSignatureWrapper
```

103 Kotlin файла, 0 Java. Все DTOs — Kotlin data classes (mutable response/
request DTOs — обычные классы с `var` для Jackson 3 setter-based deserialization).

## Тестовая инфраструктура

```
src/test/kotlin/kz/ncanode/
  TestResources.kt            ← общий helper. KalkanProvider bootstrap +
                                loadAsBase64 / loadBytes + P12_PASSWORD
  util/UtilTest.kt            ← 10 specs
  util/KalkanUtilTest.kt      ← 6
  wrapper/                    ← 4 файла, 32 specs
  service/
    CmsServiceIntegrationTest          ← 12 specs (включая addSigners)
    CertificateServiceIntegrationTest  ← 9 specs (verifyCerts, info, verify)
    XmlServiceIntegrationTest          ← 4 specs
    WsseServiceIntegrationTest         ← 3 specs
    JwtServiceIntegrationTest          ← 2 specs (GG2015)
    PdfServiceIntegrationTest          ← 5 specs (CAdES-T)
    CrlWarmupServiceTest               ← 2 specs (pure unit, MockK)

src/test/resources/
  application-test.yml        ← test profile, points to test.pki.gov.kz
  README.md                   ← полное описание test-pack'а
  ca/                         ← root_test_gost_2022.cer, nca_gost2022_test.cer
  crl/                        ← nca_gost2022_test.crl, nca_gost2022_d_test.crl
  p12/                        ← 11 ключей из NCA SDK 2.0, пароль Qwerty12:
                                individual_{valid,revoked}.p12
                                legal_{ceo,employee}_{valid,revoked}.p12
                                legal_{can_sign,treasury,infosystem}_valid.p12
                                expired_individual.p12, expired_legal_ceo.p12
                                  (период 2024-2025, истёкшие на 2026+)
  cms/, xml/, wsse/, pdf/     ← .gitkeep — артефакты генерируются in-test
```

84 теста / 70% line coverage.

## test.pki.gov.kz — официальная тестовая PKI

Интеграционные тесты ходят сюда напрямую — НЕ мокаем OCSP/TSP/CRL:

```
http://test.pki.gov.kz/cert/root_test_gost_2022.cer
http://test.pki.gov.kz/cert/nca_gost2022_test.cer
http://test.pki.gov.kz/crl/nca_gost2022_test.crl
http://test.pki.gov.kz/crl/nca_gost2022_d_test.crl
http://test.pki.gov.kz/ocsp/
http://test.pki.gov.kz/tsp/
```

Если интеграционные тесты падают на CI — проверить network доступ к этому
хосту первым делом.

## Команды (cheatsheet)

```bash
./gradlew bootJar                # сборка
./gradlew test                   # 84 теста + JaCoCo report
./gradlew test jacocoTestReport  # явно

java -jar build/libs/NCANode-4.0.0-SNAPSHOT.jar  # запуск приложения

# Просмотр coverage
open build/reports/jacoco/test/html/index.html

# Per-package summary (есть python script ниже)
```

Python helper для пер-пакетной таблицы (если нужно):
```python
import xml.etree.ElementTree as ET
tree = ET.parse("build/reports/jacoco/test/jacocoTestReport.xml")
for pkg in tree.getroot().findall("package"):
    line = next((c for c in pkg.findall("counter") if c.get("type") == "LINE"), None)
    if line:
        c, m = int(line.get("covered")), int(line.get("missed"))
        print(f"{pkg.get('name'):<40} {c}/{c+m} ({100*c//(c+m)}%)")
```

## Non-obvious quirks (история и почему)

### 1. Lombok удалён, kotlin-lombok plugin тоже
Был нужен только для DTO с `@Builder/@Data/@Jacksonized`. После полного
порта DTO в Kotlin data classes — Jackson 3 + `jackson-module-kotlin`
обрабатывает их нативно, Lombok не нужен.

### 2. Jackson 3 (tools.jackson.*), но annotations из com.fasterxml.jackson.annotation
`tools.jackson.annotation` нет на classpath. `com.fasterxml.jackson.annotation`
есть и Jackson 3 их понимает через legacy compat. **Использовать
`com.fasterxml.jackson.annotation.*`.**

### 3. StatusResponse наследники — `status`/`message` в primary constructor
Jackson 3 + kotlin-module сериализует только то, что объявлено на
конкретном классе. Если `var status: Int` сидит только на abstract
parent — `status`/`message` уйдут в конец JSON или вообще не попадут.

Поэтому каждый наследник `StatusResponse` принимает их через primary
constructor и forwards в super:
```kotlin
class CmsResponse(
    var cms: String? = null,
    status: Int = HttpStatus.OK.value(),
    message: String? = "OK",
) : StatusResponse(status, message)
```
Плюс `@JsonPropertyOrder("status", "message")` на `StatusResponse` —
гарантирует status+message в начале JSON (как было в Lombok-эпохе).

### 4. War plugin удалён
SB 4 + Gradle 9.5.1 + `war` plugin'овский `providedRuntime` фильтровал
`spring-web` из runtimeClasspath, NoClassDefFoundError на
`WebApplicationInitializer`. Никаких WAR-деплоев не делаем,
война снята.

### 5. Springdoc 3.0.3 (не 2.x)
Springdoc 2.x ссылается на `ControllerAdviceBean(Object)` constructor,
который удалён в Spring 7. Любой @ControllerAdvice → NoSuchMethodError.

### 6. wss4j 4.0 без OpenSAML
wss4j 4.x тянет OpenSAML из Shibboleth repo для SAML-token support.
NCANode WSSE — только X.509, SAML не нужен. Поэтому:
```kotlin
implementation("org.apache.wss4j:wss4j-ws-security-dom:4.0.0") {
    exclude(group = "org.opensaml")
}
```

### 7. Spring AspectJ starter
SB 4 переименовал `spring-boot-starter-aop` → `spring-boot-starter-aspectj`.
Нужен для `@EnableScheduling` + `@EnableAsync` (которые включены
в NCANode.kt).

### 8. @EnableCaching, @EnableRetry, spring-retry, starter-cache — УДАЛЕНЫ
Нет `@Cacheable` / `@Retryable` использования в коде. Раньше включались
"на всякий случай", сейчас обрезано.

### 9. CrlWarmupService — @field:Value vs @Value
Kotlin 2.3+ требует явный target. На `var` property в `@Service`
используется `@field:Value(...)` (`@param:Value` не подходит, не в primary
constructor).

### 10. @param:Qualifier на primary constructor params
То же что и #9, для `@Qualifier` на ctor-param Kotlin 2.3 предупреждает.

### 11. CertificateWrapper.fromInputStream — safe cast
`as X509Certificate` → `as? X509Certificate ?: null` — для случая когда
`generateCertificate()` возвращает не-X.509 (или null). Раньше падало с
NPE, теперь корректно возвращает `null`.

### 12. URL(String) deprecated в Java 20+
Все три места заменены на `URI(s).toURL()` (Util, TspConfiguration,
HttpClientConfiguration).

### 13. PeriodicTrigger(Long, TimeUnit) deprecated в Spring 6+
В CrlService переключён на `PeriodicTrigger(Duration.ofMinutes(...))` +
`setInitialDelay(Duration.ZERO)`.

### 14. GOST 2004 / RSA — только legacy compat в коде, тестами НЕ покрыты
НУЦ РК полностью перешла на GOST 2015. SDK 2.0 тестовых ключей других
форматов нет. Код пути для них оставлены для backward compat.

### 15. KalkanProvider bootstrap в тестах
В `TestResources.kt` есть `init` блок: `Security.addProvider(KalkanProvider())`
один раз на JVM. Без него `KalkanWrapper` и production-flow не работают.
Идемпотентный — повторный addProvider игнорируется.

### 16. JwtService.decode требует cert base64, не p12
В `JwtServiceIntegrationTest` есть helper — вытащить .encoded cert из p12
через `KeyStore.getInstance("PKCS12", KalkanProvider)`. Иначе в decode
негде взять `key`.

### 17. CaService.updateCache(true) в `beforeSpec` integration-тестов
Метод `@Scheduled(initialDelay=0)` запускается через TaskScheduler
**асинхронно**. Без явного синхронного `updateCache(true)` в beforeSpec —
первый OCSP-call в тесте может прийти раньше, чем CA bundle загрузится →
issuer = null → OCSP UNKNOWN, тест ломается случайным образом.

### 18. application-test.yml: warmupEnabled=false
Иначе integration-тесты ждут CRL warmup на startup. Lazy load работает
нормально (первый verify платит за парсинг, последующие — кеш).

## Что НЕ покрыто тестами (526 lines uncovered)

| Слой | % | Не покрыто | Почему |
|---|---|---|---|
| `service/CrlService` | 55% | ~107 lines | Defensive branches кеша + scheduler init. Нужны MockK на HttpClient |
| `service/TspService.verify` | 54% | ~56 lines | Negative paths (bad imprint, missing EKU). Нужны hand-crafted TSP-токены |
| `service/CmsService.create` | 59% | ~30 lines | Большинство покрыто, осталось NotEmpty validation в request |
| `controller/` | 24% | ~57 lines | Integration-тесты обходят HTTP-слой. Нужны `@WebMvcTest` |
| `controller/advice/` | 22% | 7 lines | ExceptionHandler не дёргается на happy-path |
| `service/CaService.shutdown()` | — | 5 lines | `System.exit` — нельзя нормально тестировать |

## Что дальше — варианты

### A. Расширить покрытие до 75-80%

Самые большие гэпы — CrlService и TspService negative paths. Нужны:
- MockK на CloseableHttpClient (для CRL/OCSP/TSP HTTP layer)
- Hand-crafted ASN.1 TSP-токены (битый imprint, missing EKU)
- `@WebMvcTest` на 4-5 контроллеров (поднимет controller с 24% → 95%)

Ориентировочно: 10-15 тестов → +5-8% покрытия.

### B. CI/CD (вероятнее всего следующая фаза)

- GitHub Actions для PR-check'а (build + test + coverage gate на 70%)
- Dependabot config (mvn deps + Gradle wrapper)
- Release workflow: tag `ncanode-v*.*.*` → build → upload bootJar to GH Releases + Docker image
- Coverage badge через codecov / coveralls

### C. Прочая зачистка

- **Баннер 3→4** — откладывали несколько раз. Заглянуть в NCANode.kt
  banner() и руками поменять.
- **`Optional<T>` в TspService.info** — был T?, переписать на T?
  если ещё не сделано.
- **`Date` → `Instant` / `LocalDateTime`** — модернизация date-types
  везде. Большая правка, низкий ROI.

### D. Merge стратегия

- `improvements` ветка: continue Java fixes, можно PR в upstream
  malikzh/NCANode
- `v4` ветка: своя жизнь. Когда созреет — стать основной в mitwork/NCANode.
- master не трогаем (он upstream-tracking).

## Структура commit'ов на v4

Историю смотри через `git log --oneline master..v4`. Логические фазы:

1. **Платформенная миграция** (commits 6935cde → b4fa9cc): Gradle Kotlin
   DSL, Java 25, SB 4, deps bumps. ~10 commits.
2. **Service layer port** (2c4f16a → a1572cf): все 15 сервисов на Kotlin.
3. **Controllers + DTO + остальное** (c2699ee → d621344).
4. **Cleanup** (9f67633 → 124aefc): warnings, dead deps, idiom drift.
5. **Test phase** (248b746 → 286854d): Kotest, NCA SDK test pack,
   70% coverage.

Все коммиты подписаны `Co-Authored-By: Claude Opus 4.7`.

## Полезные ссылки

- Upstream: https://github.com/malikzh/NCANode
- Forked: https://github.com/mitwork/NCANode (это репо)
- Demo PKI center (sister project): `/Users/zhek/IdeaProjects/demo-pki-center/`
- NCA SDK 2.0 test pack: `/Users/zhek/Downloads/SDK 2.0/Keys and Certs/`
  (источник тестовых p12 + CA + CRL)
- NCA public infrastructure:
  - pki.gov.kz — production
  - test.pki.gov.kz — официальный test PKI (используется в integration tests)
  - root.gov.kz — Root CA (КУЦ РК)

---

При продолжении работы — выбери вариант (A / B / C) и поехали.
