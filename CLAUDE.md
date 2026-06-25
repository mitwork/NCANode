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
- **Состояние v4:** functional + 203 теста / **76% coverage**.
  CI/CD обновлён под Java 25 + actions из demo-pki-center.
  Batch endpoints (issue #212) реализованы для всех сервисов.

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
| **TLS/PKI deps** | BouncyCastle bcprov/bcpkix-jdk18on 1.84, Santuario xmlsec 4.0.3, wss4j 4.0.0 (без OpenSAML), pdfbox 3.0.3, jaxws-rt 4.0.3 (SAAJ runtime для WsseService), springdoc 3.0.3 |
| **HTTP client** | JDK `java.net.http.HttpClient` (Java 11+), без внешней зависимости |
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

Все DTOs — Kotlin data classes (mutable response/request DTOs — обычные
классы с `var` для Jackson 3 setter-based deserialization).

## Batch endpoints (issue malikzh/NCANode#212)

15 batch endpoints, симметрично с одиночными. Каждый принимает массив
вместо одного элемента + общие signers/key/cert и возвращает
partial-response (per-item status + payload):

| Сервис | Endpoints |
|---|---|
| XML | `/xml/sign/batch`, `/xml/verify/batch` |
| CMS | `/cms/sign/batch`, `/cms/verify/batch`, `/cms/extract/batch` |
| WSSE | `/wsse/sign/batch`, `/wsse/verify/batch` |
| JWT | `/jwt/encode/batch`, `/jwt/decode/batch` |
| PDF | `/pdf/sign/batch`, `/pdf/verify/batch` |
| X509 | `/x509/info/batch`, `/x509/verify/batch` |
| Pkcs12 | `/pkcs12/info/batch`, `/pkcs12/aliases/batch` |

Дизайн-инварианты:

- **Общий signer/key на весь batch.** Mass-signing use case.
- **Sequential обработка items.** KalkanProvider thread-safety на GOST 2015
  без аудита не доверяем. Parallel — возможная оптимизация после нагрузки.
- **Top-level status — HTTP-уровень** (200 = "batch обработан до конца").
  Per-item status — в `results[i].status`. Aggregate-`valid` намеренно
  НЕ публикуется — клиент сам решает агрегировать в AND.
- **Status codes per item**: 200 успех; 400 client error
  (плохой p12 пароль, не-cert base64, malformed JWT); 404 NoSignaturesFound;
  500 для всего остального (ServerException и неклассифицированные).
- **DTO naming**: `<Operation>BatchRequest` / `<Operation>BatchResponse`
  с inner `Item` для sign-вариантов; verify-варианты возвращают массив
  существующих `VerificationResponse` без обёртки в Item.

## Тестовая инфраструктура

```
src/test/kotlin/kz/ncanode/
  TestResources.kt            ← общий helper. KalkanProvider bootstrap +
                                loadAsBase64 / loadBytes + P12_PASSWORD
  util/                       ← UtilTest, KalkanUtilTest
  wrapper/                    ← 4 файла: Certificate / Document / Kalkan / KeyStore
  service/
    CmsServiceIntegrationTest          ← roundtrip через test.pki.gov.kz, addSigners, batch
    CertificateServiceIntegrationTest  ← verifyCerts, info, verify, batch варианты
    XmlServiceIntegrationTest          ← sign/verify + signBatch/verifyBatch
    WsseServiceIntegrationTest         ← sign/verify + signBatch/verifyBatch
    JwtServiceIntegrationTest          ← GG2015 encode+decode + batch
    PdfServiceIntegrationTest          ← CAdES-T + signBatch/verifyBatch
    CrlServiceTest                     ← pure unit MockK: REVOKED через mock X509CRL,
                                         ACTIVE на реальных CRL, foreign-CA filter
    OcspServiceTest                    ← pure unit MockK: nonce, null issuer, HTTP errors
    TspServiceTest                     ← pure unit MockK: generateNonce, info(не-TSP)
    CrlWarmupServiceTest               ← pure unit MockK
  controller/                          ← 8 файлов + advice/, прямой вызов с MockK
    advice/ExceptionHandlerControllerAdviceTest

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

203 теста / **76% line coverage**.

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

⚠️ **NCA test-pack p12 не отзываются через CRL.** `nca_gost2022_test.crl`
содержит 54 entry, но ни одного нашего `*_revoked.p12` среди них — отзывы
для них публикуются только через OCSP. Поэтому в `CrlServiceTest`
REVOKED-ветка покрывается через mock'нутый `X509CRL`, а не реальные данные.

## Команды (cheatsheet)

```bash
./gradlew bootJar                # сборка
./gradlew test                   # 203 теста + JaCoCo report
./gradlew test jacocoTestReport  # явно

java -jar build/libs/NCANode-4.0.0-SNAPSHOT.jar  # запуск приложения

# Просмотр coverage
open build/reports/jacoco/test/html/index.html
```

Python helper для пер-пакетной таблицы:
```python
import xml.etree.ElementTree as ET
tree = ET.parse("build/reports/jacoco/test/jacocoTestReport.xml")
total_c = total_m = 0
for pkg in sorted(tree.getroot().findall("package"), key=lambda p: p.get("name")):
    line = next((c for c in pkg if c.tag == "counter" and c.get("type") == "LINE"), None)
    if line is None: continue
    c, m = int(line.get("covered")), int(line.get("missed"))
    total_c += c; total_m += m
    print(f"{pkg.get('name'):<40} {c}/{c+m} ({100*c//(c+m)}%)")
print(f"{'--- TOTAL':<40} {total_c}/{total_c+total_m} ({100*total_c//(total_c+total_m)}%)")
```

## CI / Release infra

`.github/workflows/`:

- **build-ci.yml** — push/PR на master и v4. Java 25 (temurin),
  setup-gradle@v6, codecov-action@v5. Concurrency group с
  cancel-in-progress (cancel предыдущий on push).
- **create-release.yml** — push tag `v[0-9]+.[0-9]+.[0-9]+[-*]` →
  bootJar + `gh release create --generate-notes --draft` (вместо
  устаревшего create-release@v1).
- **create-docker-release.yml** — release published → docker
  buildx push на DockerHub multi-arch (amd64/arm64).
- **github-pages.yml** — Jekyll + Swagger UI generator, master only.

Все версии actions подняты до тех, что в sister-проекте demo-pki-center
(checkout@v6, setup-java@v5, gradle/actions/setup-gradle@v6,
docker/build-push-action@v7, upload-artifact@v7 — см. коммит 7949a29).

Dockerfile: `amazoncorretto:25-alpine` (бывший 17).

## Non-obvious quirks (история и почему)

### 1. Lombok удалён, kotlin-lombok plugin тоже
Был нужен только для DTO с `@Builder/@Data/@Jacksonized`. После полного
порта DTO в Kotlin data classes — Jackson 3 + `jackson-module-kotlin`
обрабатывает их нативно, Lombok не нужен. `lombok.config` удалён
в коммите 20b6ad9.

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

Касается и всех batch-response типов (`*BatchResponse` + inner `Item`).

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

### 7. jaxws-rt — это SAAJ runtime для WsseService, не "JAX-WS"
`com.sun.xml.ws:jaxws-rt:4.0.3` нужен потому что
`kz.ncanode.service.WsseService` использует `jakarta.xml.soap.MessageFactory`
для парсинга/перепаковки SOAP envelope'ов. wss4j подтягивает только
API `jakarta.xml.soap-api`, реализацию SAAJ нужно дать явно. `jaxws-rt`
её тащит. `jakarta.xml.ws-api` отдельно НЕ нужен — был удалён в 20b6ad9.

### 8. Spring AspectJ starter
SB 4 переименовал `spring-boot-starter-aop` → `spring-boot-starter-aspectj`.
Нужен для `@EnableScheduling` + `@EnableAsync` (которые включены
в NCANode.kt).

### 9. @EnableCaching, @EnableRetry, spring-retry, starter-cache — УДАЛЕНЫ
Нет `@Cacheable` / `@Retryable` использования в коде.

### 10. CrlWarmupService — @field:Value vs @Value
Kotlin 2.3+ требует явный target. На `var` property в `@Service`
используется `@field:Value(...)` (`@param:Value` не подходит, не в primary
constructor).

### 11. @param:Qualifier на primary constructor params
То же что и #10, для `@Qualifier` на ctor-param Kotlin 2.3 предупреждает.

### 12. CertificateWrapper.fromInputStream — safe cast
`as X509Certificate` → `as? X509Certificate ?: null` — для случая когда
`generateCertificate()` возвращает не-X.509 (или null). Раньше падало с
NPE, теперь корректно возвращает `null`.

### 13. URL(String) deprecated в Java 20+
Все три места заменены на `URI(s).toURL()` (Util, TspConfiguration,
HttpClientConfiguration).

### 14. PeriodicTrigger(Long, TimeUnit) deprecated в Spring 6+
В CrlService переключён на `PeriodicTrigger(Duration.ofMinutes(...))` +
`setInitialDelay(Duration.ZERO)`.

### 15. GOST 2004 / RSA — только legacy compat в коде, тестами НЕ покрыты
НУЦ РК полностью перешла на GOST 2015. SDK 2.0 тестовых ключей других
форматов нет. Код пути для них оставлены для backward compat.

### 16. KalkanProvider bootstrap в тестах
В `TestResources.kt` есть `init` блок: `Security.addProvider(KalkanProvider())`
один раз на JVM. Без него `KalkanWrapper` и production-flow не работают.
Идемпотентный — повторный addProvider игнорируется.

### 17. JwtService.decode требует cert base64, не p12
В `JwtServiceIntegrationTest` есть helper — вытащить .encoded cert из p12
через `KeyStore.getInstance("PKCS12", KalkanProvider)`. Иначе в decode
негде взять `key`.

### 18. CaService.updateCache(true) в `beforeSpec` integration-тестов
Метод `@Scheduled(initialDelay=0)` запускается через TaskScheduler
**асинхронно**. Без явного синхронного `updateCache(true)` в beforeSpec —
первый OCSP-call в тесте может прийти раньше, чем CA bundle загрузится →
issuer = null → OCSP UNKNOWN, тест ломается случайным образом.

### 19. application-test.yml: warmupEnabled=false
Иначе integration-тесты ждут CRL warmup на startup. Lazy load работает
нормально (первый verify платит за парсинг, последующие — кеш).

### 20. ExceptionHandlerControllerAdvice.handleRuntimeException — public, не protected
Изменено в коммите 01fab53. Spring дёргает @ExceptionHandler через
reflection в любом случае; protected мешало unit-тестам напрямую вызвать
метод без поднятия Spring MVC. Стандартная практика — public.

### 21. CrlService.verify REVOKED — через mock X509CRL, не реальный
NCA публикует отзывы наших test-pack p12 только через OCSP. В CRL'ях
`nca_gost2022_test.crl` (54 entry) + delta (0 entry) их нет. CrlServiceTest
покрывает pipeline `verify` через mock'нутый X509CRL.isRevoked → true.
Сам JDK-овый X509CRL.isRevoked не тестируем — это библиотечный код.

### 22. Batch endpoints — partial response, top-level всегда 200
См. отдельный раздел "Batch endpoints" выше. Aggregate `valid` намеренно
не добавлен на top-level: для mass-flow вреднее прятать ошибку в одном
из item'ов, чем требовать от клиента ручного AND.

### 23. HTTP client — JDK `java.net.http.HttpClient`, не Apache
В v4 был мигрирован с Apache `httpclient:4.5.14` на JDK-native клиент.
Конфигурационные особенности:
- **Redirect policy: `NEVER`.** RFC 5280 запрещает редиректы в URL'ах
  CRL DP / OCSP / AIA. Видим misconfiguration сразу через 303-error,
  а не следуем тихо.
- **HTTP version: forced `HTTP_1_1`.** PKI-серверы (pki.gov.kz, ocsp,
  tsp) все HTTP/1.1; ALPN-negotiate добавляет latency и иногда фейлится.
- **`proxy(HttpClient.Builder.NO_PROXY)`** даже если system property
  установлен — Apache 4.x игнорировал системные настройки, держим
  совместимость. Свой прокси — через `NCANODE_PROXY_URL`.
- **Basic-auth через прокси по HTTPS-туннелю.** JDK по дефолту отключён
  (CVE-fix). При наличии `NCANODE_PROXY_USERNAME` в `configureProxy()`
  снимаем `jdk.http.auth.tunneling.disabledSchemes` и `proxying.*`
  через `System.setProperty`.
- **Total request timeout = `requestTimeout` в секундах.** В Apache 4.x
  не было — только `socketTimeout` (между чтениями). Теперь
  `HttpRequest.timeout()` даёт честный бюджет на запрос.

### 24. User-Agent: пустой UA триггерит фильтры IPS на пути к pki.gov.kz
Наблюдалось: запрос с `User-Agent: ` (header без значения) к
`test.pki.gov.kz` получает **HTTP 303** с Location на Check Point
captive portal (`http://192.168.119.249/UserCheck/PortalMain?...`).
Reproduce: воспроизводилось из Gradle test executor на macOS, **не**
воспроизводилось из standalone `java` процесса с тем же JDK. Trigger —
именно пустой UA: с любым непустым значением (`NCANode/null`,
`curl/8.0`, что угодно) получаем 200.

Фильтр на стороне канала между NIT/Astana IX и pki.gov.kz, не у нас.
В коде: `HttpClientConfiguration.effectiveUserAgent` возвращает
`NCANode/<version>` если `userAgent` blank, иначе сам `userAgent`.
Сервисы (CaService/CrlService/OcspService/TspService) обязаны
использовать `effectiveUserAgent`, не сырое поле. **Никогда не отправлять
empty User-Agent.**

### 25. Production TSA подписывает метки RSA-сертификатом → nca_rsa_2022.cer обязателен в CA bundle
Реальный кейс (июнь 2026): CMS с GOST2015-512 подписантом, TSP от
`tsp.pki.gov.kz`, verify с OCSP+CRL → `valid: false`, `tsp: null` при
полностью валидном подписанте. Причина: TSP-метка в CMS, созданном
сторонним клиентом (НЕ нашим `/cms/sign`), подписана TSA-сертификатом
`CN=TIME-STAMPING AUTHORITY` от **НУЦ (RSA) 2022** (sha256RSA, imprint
SHA-256), а `nca_rsa_2022.cer` отсутствовал в дефолтном `NCANODE_CA_URL`
(там был только legacy `nca_rsa.crt`). Строгая CAdES-T проверка v4
(`TspService.verify`, отсутствует в upstream) не нашла issuer'а TSA →
`isValid=false` → WARN `TSA certificate is not valid at TSP genTime` →
весь CMS invalid. Upstream NCANode v3 цепочку TSA вообще не проверяет,
поэтому там «работало».

Нюанс: какой TSA-сертификат вернёт НУЦ — зависит от policy/hash в
запросе клиента. Наш `/cms/sign` (gost2015 policy + GOST3411-2015-512)
получает GOST-TSA от НУЦ (GOST) 2022; сторонние клиенты с SHA-256
получают RSA-TSA от НУЦ (RSA) 2022. Фикс: `nca_rsa_2022.cer` добавлен в
дефолтный `NCANODE_CA_URL` (application.yml). При диагностике
`valid:false + tsp:null` — первым делом `grep -E "WARN.*(TSP|TSA)"` в
логах: каждая ветка отказа в `TspService.verify` пишет свой WARN.

### 26. Отзыв проверяется темпорально относительно времени подписи (CAdES-T), а не «отозван сейчас?»
Реальный кейс (июнь 2026): multi-sign CMS, один подписант поставил подпись
валидным ключом (TSP genTime 05:48:41), через ~4,5 минуты перевыпустил
сертификат → старый отозван через OCSP в 05:53:13 с reason **SUPERSEDED**.
Verify возвращал `valid:false`, потому что `CertificateWrapper.isValid`
проверял revocation **бинарно** — `ocspStatus.all { isActive }` /
`crlStatus.result == ACTIVE` — игнорируя и `revocationTime`, и
`validationDate`. Получалась асимметрия: срок действия проверялся на
genTime (правильно), а отзыв — на «сейчас», и отзыв, случившийся *после*
подписи, ретроактивно убивал валидную подпись. Top-level `valid` — AND,
поэтому падал весь CMS из-за одного подписанта.

Фикс: `OcspStatus.isValidAt(signingTime)` / `CrlStatus.isValidAt(signingTime)`
+ `kz.ncanode.dto.certificate.RevocationPolicy`. Отозванный сертификат
считается добропорядочным на момент подписи, если отзыв случился **строго
позже** `signingTime` (= genTime при доверенной TSP-метке, иначе
currentDate) **и** по benign-причине: `affiliationChanged`, `superseded`,
`cessationOfOperation`, `privilegeWithdrawn`. Ретроактивно (всегда invalid):
`keyCompromise` / `caCompromise` / `aaCompromise` (компрометация не доверяема
и до формального отзыва), а также — консервативно — `unspecified`,
`certificateHold`, отсутствие причины/времени отзыва.

Важно: без TSP-метки `validationDate = currentDate`, и отзыв в прошлом так
и остаётся invalid (`revocationTime.after(now)` = false) — нечем доказать,
что подписал до отзыва. Поэтому фикс «бесплатно» завязан на тот же genTime,
что уже использовался для срока. OCSP отдаёт причину int-кодом RFC 5280
§5.3.1 (== ordinal `CRLReason`), CRL — именем enum; `RevocationPolicy`
нормализует оба в `java.security.cert.CRLReason`. JSON `revocations[]`
по-прежнему показывает `revoked:true` + reason — это честно; меняется
только итоговый `valid`. Покрытие: `RevocationTemporalTest` (19 кейсов) +
5 integration в `CertificateWrapperTest`.

Про долгосрочную проверку: revocation-данные добираются **вживую** на
verify, а не вшиты на момент подписи (это был бы CAdES-X-Long/-A, в v4 нет).
Теоретический риск — OCSP со временем вернёт UNKNOWN по истёкшему ключу, и
тогда `isValid` отклонит (UNKNOWN → invalid). Эмпирически проверено
(`OcspExpiredCertDiagnosticTest`): OCSP test.pki.gov.kz по cert'у, истёкшему
~8 месяцев назад, **всё ещё отдаёт ACTIVE**, не UNKNOWN (RFC 6960 — OCSP про
отзыв, не про срок). Значит для практического горизонта live-OCSP +
темпоральный фикс самодостаточны, и X-Long отложен. Тест — канарейка: если
НУЦ когда-нибудь начнёт purge'ить истёкшие серийники, его вывод покажет
UNKNOWN. Не проверено на проде (pki.gov.kz) и на горизонте 10+ лет.

### 27. RFC-аудит PKI: verification-contract фиксы (пункт 1)
Multi-agent аудит всей PKI-логики на соответствие RFC дал **12
подтверждённых** находок (из 35, 23 отсеяны верификаторами). Отчёт —
`pki-rfc-audit-report.md`, план остатка — `pki-rfc-audit-plan.md` (оба в
корне репо, **не** для upstream-PR — рабочие артефакты v4). Корневая
причина всех HIGH: `VerificationResponse` отдаёт плоский `valid`, не
сообщая, ЧТО именно покрыто подписью.

Закрыт **пункт 1** (3 находки):
- **CMS с 0 подписантов** (RFC 5652 §5.1): пустой `signerInfos` проходил
  цикл вхолостую → `valid=true`. Фикс — `if (signerCerts.isEmpty()) return
  valid=false` ДО цикла (`CmsService.verify`).
- **Подписант без cert в store** (RFC 5652 §5.6): если `certStore`
  .getCertificates(sid) пуст, внутренний `for (cert in certs)` не
  выполнялся → `signer.verify()` не вызывался → подписант молча ОК. Фикс —
  guard `if (certs.isEmpty()) valid=false` per-signer.
- **Delegated OCSP-responder** (RFC 6960 §4.2.2.2): cert responder'а
  проверялся на цепочку+EKU, но не на validity. Фикс в
  `findVerifiedResponderCertificate` — `checkValidity(producedAt)` + учёт
  `id-pkix-ocsp-nocheck` (1.3.6.1.5.5.7.48.1.5).

Закрыт **пункт 2** — покрытие документа подписью (что именно подписано,
а не только что подпись крипто-валидна):
- **XML-DSig XSW** (xmldsig-core): `check()` валидирует дайджесты, но не что
  Reference покрывает весь документ. Фикс — `XMLSignatureWrapper.coversWholeDocument()`:
  требуем Reference с пустым URI (whole-document enveloped) + только безопасные
  transforms (enveloped + c14n; XPath/XSLT сужают node-set → дисквалификация).
  `XmlService.verify` отвергает подпись без whole-document Reference.
- **PDF PAdES** (ISO 32000-1 §12.8.1): verify проверял CMS над байтами
  `/ByteRange`, но не что ByteRange покрывает весь файл → incremental-update
  forgery. Фикс — `PdfService.signatureCoversWholeDocument()` (0..EOF, дыра только
  под `/Contents`); на уровне документа требуем, чтобы ХОТЯ БЫ ОДНА подпись
  покрывала весь файл (multi-sign safe: последняя подписывает предыдущие ревизии).
  Новый флаг `PdfSignerInfo.coversWholeDocument`.
- **WSSE XSW** (WSS X.509): verify не проверял, что подпись покрывает реальный
  SOAP Body. Фикс — регистрируем `wsu:Id` ровно на настоящем Body (Reference `#id`
  резолвится в него), `secureValidation=true` (блок duplicate-id), явная проверка
  `signatureReferencesId(body)`; битая подпись → valid=false, не 500.

Закрыт **пункт 3** — LOW conformance:
- **3.2** NPE на cert без keyUsage: `fromKeyUsageBits(BooleanArray?)` →
  `null`/короткий → UNKNOWN (RFC 5280 §4.2.1.3, keyUsage OPTIONAL).
- **3.1** TSA EKU строго (RFC 3161 §2.3): id-kp-timeStamping ЕДИНСТВЕННЫЙ +
  critical. NCA GOST TSA конформен (`TsaCertDiagnosticTest` это стережёт).
- **3.3** critical-ext (cert): явный allowlist {keyUsage, basicConstraints,
  EKU, SAN, certPolicies}; critical вне набора → reject (RFC 5280 §4.2).
- **3.4** critical-ext (CRL): любое critical-расширение → skip CRL (§5.2).

⚠️ **Грабли пункта 3**: `X509Certificate/X509CRL.hasUnsupportedCriticalExtension()`
в Kalkan/BC считает **critical extendedKeyUsage** «неподдержанным» — а RFC 3161
ТРЕБУЕТ critical EKU у TSA. Наивное использование этого флага в 3.3 отвергало
конформный TSA-cert → `TspService.verify` возвращал null → весь CAdES-T
ломался (4 CMS + 1 PDF теста красные). Поэтому critical-ext проверки — только
через явные allowlist'ы по OID, НЕ через BC-флаг.

**Ремедиация завершена**: все HIGH/MEDIUM (пункты 1–2) + значимые LOW
(пункт 3) закрыты. Пункт 4 (`pki-rfc-audit-plan.md`) — **осознанно отложен**:
редизайн trust-решения через JDK `CertPathValidator`/`PKIXRevocationChecker`
закрыл бы две оставшиеся LOW (RFC 5280 §6 path-constraints + revocation
промежуточных CA), но это архитектурный редизайн с высоким риском GOST-регрессии
(штатный PKIX-валидатор может не пройти GOST-цепочку НУЦ через Kalkan) ради
LOW-пунктов без known-эксплойта. Триггер пересмотра — реальное появление
nameConstraints/policyConstraints у промежуточных CA или требование строгой
per-request revocation промежуточных CA (см. план, раздел «Триггер пересмотра»).

## Что не покрыто тестами (≈494 lines)

| Слой | % | Что осталось |
|---|---|---|
| `service` overall | 74% | TspService.verify negative paths (битый imprint, missing EKU) — нужны hand-crafted ASN.1 TSP-токены; CaService.shutdown() — System.exit |
| `controller` | 98% | HomePageController IO error path (один невозможный case) |
| `controller/advice` | 100% | — |
| `util` | 78% | Defensive branches в KalkanUtil |
| `wrapper` | 78% | Defensive branches в DocumentWrapper |

OCSP/CRL/TSP HTTP-bootstrap fixtures (заранее сохранённые `.bin` ответы
для оффлайн-тестов REVOKED/ACTIVE/UNKNOWN на mismatch nonce) — пока
не сделаны. Сейчас эти ветки покрываются через `CmsServiceIntegrationTest`
с live test.pki.gov.kz.

## Что дальше — варианты

### A. Дальнейший рост покрытия (76% → 80%)

Самые крупные оставшиеся гэпы:
- TspService.verify negative paths — нужны hand-crafted ASN.1 TSP-токены
  (битый messageImprint, missing EKU id-kp-timeStamping). +~30 lines.
- OCSP fixtures bootstrap (опциональный @Tags("bootstrap") test'ник
  для генерации `.bin` ответов с известным nonce; затем pure-unit
  REVOKED/ACTIVE/UNKNOWN-mismatch-nonce). +~20 lines.

### B. Прочая зачистка

- **Баннер 3→4** — откладывали несколько раз. Заглянуть в NCANode.kt
  banner() и руками поменять.
- **`Date` → `Instant` / `LocalDateTime`** — модернизация date-types
  везде. Большая правка, низкий ROI.

### C. Merge стратегия

- `improvements` ветка: continue Java fixes, можно PR в upstream
  malikzh/NCANode
- `v4` ветка: своя жизнь. Когда созреет — стать основной в mitwork/NCANode.
- master не трогаем (он upstream-tracking).

## Структура commit'ов на v4

Историю смотри через `git log --oneline master..v4`. Логические фазы:

1. **Платформенная миграция**: Gradle Kotlin DSL, Java 25, SB 4, deps bumps.
2. **Service layer port**: все 15 сервисов на Kotlin.
3. **Controllers + DTO + остальное** (`c2699ee → d621344`).
4. **Cleanup**: warnings, dead deps, idiom drift.
5. **Test phase** (`248b746 → 286854d`): Kotest, NCA SDK test pack, 70% coverage.
6. **CLAUDE.md** (`dd7ac1f`): этот файл.
7. **Hardening session** (`20b6ad9 → 01fab53`): legacy deps cleanup,
   README rewrite, CI bump до Java 25, service unit tests
   (Crl/Ocsp/Tsp), controller + advice tests (24% → 98%).
   Покрытие 70% → 75%.
8. **Batch endpoints** (`472d80b → bd2672c`): issue malikzh/NCANode#212.
   15 endpoint'ов в 4 round'а: XML/CMS sign+verify → WSSE/CMS-extract/JWT/PDF
   → X509-info/Pkcs12-info → X509-verify(SBA)/Pkcs12-aliases.
   Покрытие 75% → **76%**, тесты 96 → 163.
9. **HTTP client → JDK**: миграция с Apache `httpclient:4.5.14` на
   `java.net.http.HttpClient`. Total request timeout, redirect NEVER,
   forced HTTP_1_1, NO_PROXY explicit. Все 4 сервиса (Ca/Crl/Ocsp/Tsp)
   + тесты. Apache deps удалены. Тесты 163 → 164, coverage 76% → 75%
   (-1% за счёт configureProxy без unit-теста).

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
