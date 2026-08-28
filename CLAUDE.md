# CLAUDE.md — onboarding context for NCANode v4

Этот файл — контекст для возобновления работы (в т.ч. с другого
компьютера). Содержит: что сделано, где что лежит, чем продолжать.

## TL;DR

- **Текущая ветка:** `v4`. Это полная переписка NCANode с Java/Spring Boot
  2.7 + Lombok на 100% Kotlin / Spring Boot 4.0 / Java 25 / Gradle 9.
- **Ветки в работе:**
  - `feature/ades-levels` — CAdES/XAdES/PAdES уровней B/T/LT/LTA под
    обновлённый NCALayer. Подписание и проверка готовы, осталось batch и
    сверка на эталонных подписях НУЦ. План — `ades-levels-plan.md`,
    quirk #38.
  - `perf/crl-memory` — экономия памяти на CRL (mmap-индекс, cap на размер,
    LRU для on-demand). PR #11 в `v4`.
- **Параллельная ветка:** `improvements` — Java версия с теми же
  improvements'ами (CRL cache, OCSP parallel, CAdES-T fixes, request log,
  health indicator). Сохранена для возможности PR'а в upstream
  malikzh/NCANode. v4 в upstream не пойдёт (другой язык).
- **Состояние v4:** functional + 384 теста / **86% coverage**
  (после вливания `feature/ades-levels`).
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
| **Кriptoprovider** | Kalkan 0.7.8 + kalkancrypt-xmldsig 0.5 (flatDir `lib/`) |
| **TLS/PKI deps** | BouncyCastle bcprov/bcpkix-jdk18on 1.84, Santuario xmlsec 4.0.3, wss4j 4.0.0 (без OpenSAML), pdfbox 3.0.3, jaxws-rt 4.0.3 (SAAJ runtime для WsseService), springdoc 3.0.3 |
| **HTTP client** | JDK `java.net.http.HttpClient` (Java 11+), без внешней зависимости |
| **Тесты** | Kotest 6.2 (JUnit 5 runner) + MockK 1.14 + spring-boot-starter-test |

Build clean (zero warnings). `./gradlew bootJar` зелёный.

## Архитектура — single module

```
src/main/kotlin/kz/ncanode/
  NCANode.kt                  ← @SpringBootApplication + main + banner
  ades/                       ← машинерия AdES-форматов (без Spring), quirk #38
  configuration/              ← @Configuration beans + RequestLoggingFilter
    crl/                      ← CrlConfiguration interface + 2 наследника
  constants/MessageConstants  ← object с const val (error message keys)
  controller/                 ← 11 контроллеров (10 @RestController) + advice/
  crl/                        ← Der, CrlScanner, CrlIndex — потоковый разбор CRL
                                и mmap-индекс отзывов (см. quirk #34)
  dto/
    ades/, certificate/, cms/, crl/, http/, ocsp/, pdf/, request/, response/, tsp/
  exception/                  ← 8 классов, ApplicationException base
  service/                    ← 17 файлов (16 @Service + CrlService из @Configuration)
  util/                       ← Util, KalkanUtil, KeyUtil (top-level functions, @file:JvmName)
  wrapper/                    ← CertificateWrapper, KeyStoreWrapper, KalkanWrapper, DocumentWrapper, XMLSignatureWrapper
```

Все DTOs — Kotlin data classes (mutable response/request DTOs — обычные
классы с `var` для Jackson 3 setter-based deserialization).

## Batch endpoints (issue malikzh/NCANode#212)

21 batch endpoint, симметрично с одиночными. Каждый принимает массив
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
| CAdES | `/cades/sign/batch`, `/cades/verify/batch` |
| XAdES | `/xades/sign/batch`, `/xades/verify/batch` |
| PAdES | `/pades/sign/batch`, `/pades/verify/batch` |

Дизайн-инварианты:

- **Общий signer/key на весь batch.** Mass-signing use case. У AdES-семейств
  общий и **уровень**: смешивать в одном запросе B и LTA незачем, а разный
  уровень на элемент сделал бы неоднозначным частичный отказ на LT.
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

## AdES-эндпойнты (CAdES / XAdES / PAdES, уровни B–T–LT–LTA)

Ветка `feature/ades-levels`. Подробности и обоснование решений —
`ades-levels-plan.md`; здесь только карта.

| Формат | Эндпойнты | Опирается на |
|---|---|---|
| CAdES | `/cades/sign`, `/cades/verify` | `CmsService` |
| XAdES | `/xades/sign`, `/xades/verify` | `XmlService` |
| PAdES | `/pades/sign`, `/pades/verify` | `PdfService` |

⚠️ **LTA + одна и та же подпись дважды одним сертификатом**: контейнер
корректен, но валидатор НУЦ отвергает архивную метку второй подписи — он ищет
подписанта по SID, который у них совпадает (тот же баг, что мы у себя
починили). Проверено парой контейнеров, отличавшихся только этим. `coSign`
пишет об этом WARN. Разбор — `ades-levels-plan.md`.

⚠️ Архивная метка CAdES: содержимое передаётся в `imprintInput` **явно**
(у detached его в контейнере нет — раньше в расчёт уходил хэш пустоты), а
`SignerInfo` ищется по значению подписи, а не по SID (у двух подписей одним
ключом SID одинаков). Обе ошибки своей же проверкой не ловились — она
повторяла тот же расчёт; нашлись на живом валидаторе NCALayer. Многоподписный
XAdES с ним пока несовместим, см. `ades-levels-plan.md`.

⚠️ Данные об отзыве считаются свидетельством о моменте `at`, если их интервал
его накрывает **либо** они выпущены позже `at`, но до `notAfter` сертификата
(отзыв необратим и датирован; после истечения запись могут убрать). Без второй
половины `extend` бессмыслен — материал для него собирается уже после подписи.
`fresh` — отдельное, строгое понятие: только оно решает, заменяет ли CRL
упавший OCSP (quirk #28).

Повышение уровня готовой подписи — `/{cades,xades,pades}/extend`, без ключа
и без нового подписанта (у PAdES только LT и LTA). Нужно потому, что
AdES-методы NCALayer живут только в его окнах: сайту через веб-сокет доступны
лишь обычные CMS- и XML-подписи, то есть LT/LTA в браузере не получить.

Доподписание (подписант «вторым по маршруту»): для XAdES и PAdES — подать
подписанный документ на подпись снова, для CAdES — `PATCH /cades/sign`
(поле `cms`). Для AdES-контейнеров НЕ использовать `PATCH /cms/sign`: он
теряет поле `crls` с материалом уровня LT и добавляет подписанта без
AdES-атрибутов.

Старые `/cms/*`, `/xml/*`, `/pdf/*` **не легаси** — работают как раньше.
Новые сервисы ходят в них через швы с дефолтным параметром `prepare`
(без аргумента — прежний путь один в один).

Batch есть у всех трёх — см. таблицу в разделе «Batch endpoints».

## Тестовая инфраструктура

```
src/test/kotlin/io/kotest/provided/
  ProjectConfig.kt            ← Kotest 6 project config (FQN-конвенция!) —
                                глобальный SpringExtension, см. quirk #33
src/test/kotlin/kz/ncanode/
  TestResources.kt            ← общий helper. KalkanProvider bootstrap +
                                loadAsBase64 / loadBytes + P12_PASSWORD
  crl/CrlIndexTest            ← эквивалентность потокового разбора JDK-парсеру
                                (посписочно по всем 54 записям реального CRL),
                                GOST-подпись, sidecar, битый индекс, не-CRL
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
    CadesServiceIntegrationTest        ← B/T/LT/LTA, detached, негативы (18)
    XadesServiceIntegrationTest        ← B/T/LT/LTA enveloped (20)
    PadesServiceIntegrationTest        ← B/T/LT/LTA, /DSS, видимая подпись,
                                         политика хвоста (22)
  ades/CadesInspectorTest              ← разбор уровня и привязки (7)
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

⏰ **ДЕДЛАЙН: valid-ключи истекают 2027-05-07** (период валидности
2026-05-08…2027-05-07). После этой даты КАЖДЫЙ roundtrip-тест (CMS/XML/WSSE/
JWT/PDF/X509/PKCS12) начнёт возвращать `valid=false` из-за `isDateValid`, и
`CertificateWrapperTest` («…valid period in 2026») тоже упадёт — это
детерминированная поломка всей интеграционной части. Плюс `*_revoked.p12`
зависят от того, что OCSP test.pki.gov.kz продолжает отдавать REVOKED по их
серийникам (после ротации SDK-пака слетит). Процедура обновления: перекачать
NCA SDK 2.0 test pack, заменить p12 в `p12/`, сверить новый период валидности,
обновить эту дату.

256 тестов / **82% line coverage**.

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
REVOKED-ветка покрывается через mock'нутый `CrlIndex`, а не реальные данные.

## Команды (cheatsheet)

```bash
./gradlew bootJar                # сборка
./gradlew test                   # 256 тестов + JaCoCo report
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

**Dependabot** — `.github/dependabot.yml`: gradle + github-actions + docker,
weekly (пн 06:00 Asia/Almaty), все PR через `target-branch: v4`. Gradle
minor/patch группируются в один PR, major'ы отдельно; corretto major в
Dockerfile игнорируется (JVM bump — руками, синхронно с toolchain).
Default branch форка переключён на **v4** (июль 2026) — конфиг читается
с него, security-апдейты тоже целятся в v4.
⚠️ Dependabot-PR запускают build-ci.yml без обычных secrets:
`KALKAN_CRYPT_URL`/`KALKAN_CRYPT_XMLDSIG_URL` продублированы в
Settings → Secrets and variables → **Dependabot**. Kalkan (flatDir) и
`kz.gov.pki:java-jwt` (Azure feed) Dependabot не резолвит — руками.

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
Нужен для `@EnableScheduling` (в NCANode.kt). `@EnableAsync`/`AsyncConfiguration`
удалены в аудите P2 (quirk #32): `@Async` нигде не использовался, а executor
был неинициализирован.

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
покрывает pipeline `verify` через mock'нутый `CrlIndex.find` → RevokedEntry
(до quirk #34 — через mock'нутый `X509CRL.isRevoked`). Сам поиск по индексу
проверяется отдельно в `CrlIndexTest` на реальных данных.

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

### 28. OCSP→CRL fallback при сетевой недоступности OCSP (без конфиг-флага)
Мотивация: реальные проблемы с availability OCSP у пользователя; строгий AND
(`revocationCheck: [OCSP, CRL]`) ронял verify при упавшем OCSP, хотя валидный
CRL лежал в кэше. Дизайн (июль 2026):

- **`OcspResult.UNAVAILABLE` ≠ `UNKNOWN`.** UNAVAILABLE — транспортный сбой
  (IOException/InterruptedException в `OcspService.verify`, включая unparseable
  body: `OCSPResp(garbage)` кидает IOException) — ответа НЕТ ВОВСЕ. UNKNOWN —
  ответ есть, но доверия нет (nonce mismatch, битая подпись, статус != 0) —
  security fail-closed, fallback ЗАПРЕЩЁН (иначе MITM выталкивал бы verify
  на отстающий CRL).
- **`CrlResult.UNAVAILABLE`** — «проверять было нечем»: CRL выключен конфигом,
  нет CRL издателя в кэше, все сматчившиеся отброшены фильтрами. Заменяет
  прежний фиктивный `ACTIVE` в этих случаях. В AND-режиме НЕфатален
  (легаси-CA без CRL — легитимный случай, сохранена старая семантика), но
  fallback-источником быть не может. `CaService` не задет — он сверяет
  только `== REVOKED`.
- **`CrlStatus.fresh`** — ACTIVE опирается хотя бы на один CRL с
  `nextUpdate >= now`. Fallback принимает ТОЛЬКО fresh ACTIVE — протухший CRL
  остаётся детектором отзыва, но не единоличным основанием валидности.
  `nextUpdate == null` → не fresh (консервативно, RFC 5280 §5.1.2.5).
- **Матрица в `CertificateWrapper.isValid`**: любой авторитетный плохой OCSP
  (UNKNOWN / непрощённый REVOKED) → invalid; хотя бы один ACTIVE → OCSP-вердикт
  есть (UNAVAILABLE остальных URL нефатален); ВСЕ UNAVAILABLE (или пустой
  список — раньше проходил вакуумно через `all{}`) → valid только если
  `checkCrl && crlStatus.result == ACTIVE && fresh`.
- **Без конфиг-флага, осознанно**: установленной базы v4 нет, поведение —
  дефолт эталонных реализаций (JDK `PKIXRevocationChecker`); ограничивающий
  флаг добавить потом обратно-совместимо, менять default — нет. Строгость
  доступна клиенту: `revocations[].result` (`RevocationResult` enum, новое
  поле в `CertificateRevocationStatus`) показывает UNAVAILABLE — старый AND =
  `valid && revocations.none { result == UNAVAILABLE }`; либо
  `revocationCheck: [OCSP]` (OCSP-only, UNAVAILABLE фатален — некуда падать).
- Покрытие: fallback-матрица в `CertificateWrapperTest` (8 кейсов), freshness
  в `CrlServiceTest` (3), реклассификация сетевых ошибок в `OcspServiceTest`.
  Docs: `docs/_tabs/docs.md`, раздел «Проверка отзыва сертификатов».

### 29. Actuator + Prometheus endpoint (exposure = health,info,prometheus)
Actuator был подключён и раньше (`starter-actuator` + кастомный
`CrlWarmupHealthIndicator` → `/actuator/health`), но метрик наружу не было.
Добавлено:
- `io.micrometer:micrometer-registry-prometheus` (версия из SB BOM →
  `1.17.0`) в `build.gradle.kts`.
- Блок `management` в `application.yml`: наружу выставлены ровно
  `health,info,prometheus` (env `NCANODE_ACTUATOR_ENDPOINTS` переопределяет
  список; `NCANODE_PROMETHEUS_ENABLED` выключает экспорт). Не открываем
  весь actuator — env/beans/… остаются 404.

Грабли SB4/наблюдения:
- **`endpoint.prometheus.access: read-only`**, НЕ устаревший `enabled: true`
  (SB 3.4+ заменил `enabled` на `access: none|read-only|unrestricted`).
- **Путь экспортёра `management.prometheus.metrics.export.enabled`** — в
  SB 3.4+ переехал из `management.metrics.export.prometheus.enabled`.
- **`TestRestTemplate` УДАЛЁН в Spring Boot 4** (`spring-boot-test` его
  больше не содержит; `LocalServerPort` остался). В `ActuatorEndpointTest`
  ходим по HTTP через JDK `HttpClient` (как и прод), порт — из
  `Environment.getRequiredProperty("local.server.port")`. Плюс: JDK-клиент
  не бросает на 4xx — удобно проверять 404 на невыставленный эндпойнт.
- `/actuator/*` уже исключён из request-log (`RequestLoggingFilter`), скрейп
  Prometheus лог не засоряет.
- Покрытие: `ActuatorEndpointTest` (5 кейсов, `@SpringBootTest` RANDOM_PORT):
  health UP / info / prometheus text-формат / discovery-листинг / env→404.
  Сети не требует (actuator не зависит от CA/OCSP/TSP).

### 30. Delta-CRL: настоящий RFC 5280 §5.2.4 merge (не «ещё один full»)
Раньше `CrlService.verify` перебирал CRL-файлы независимо и **выбрасывал**
delta из-за её `critical deltaCRLIndicator` (общий фильтр «любое critical →
skip»). То есть delta качалась (свой URL, TTL 60мин), но в проверке
не участвовала. Дыра именно в контексте OCSP→CRL fallback (quirk #28):
fallback принимает только `fresh` ACTIVE, а `fresh` считался по full CRL;
досрочный отзыв, опубликованный НУЦ в delta но ещё не попавший в full,
был невидим → при упавшем OCSP fallback ложно принял бы отозванный cert.

Боевые данные НУЦ (проверено `crl.pki.gov.kz`, июль 2026):
- full `nca_gost_2022.crl`: ~21.6 МБ, `nextUpdate` ~27ч, `CRLNumber`=1346,
  перевыпускается ~ежедневно (Last-Modified меняется досрочно);
- delta `nca_d_gost_2022.crl`: ~32 КБ, `nextUpdate` ~7.5ч,
  `deltaCRLIndicator`(baseCRLNumber)=1346 == full.CRLNumber, `CRLNumber`=57725.
  Полностью конформна RFC 5280 §5.2.4 — **баг-репорт в НУЦ не нужен**
  (ранняя гипотеза про «nextUpdate 6 месяцев» была из протухшего снапшота
  `test.pki.gov.kz`, на проде это ~27ч).

Реализация (`CrlService.verify` + хелперы):
- delta больше не skip: CRL-allowlist критичных расширений =
  `{deltaCRLIndicator 2.5.29.27}` (`SUPPORTED_CRITICAL_CRL_EXTENSIONS`),
  прочее critical по-прежнему дисквалифицирует CRL.
- Собираем пригодные CRL издателя, делим на base/delta по наличию
  `deltaCRLIndicator`. Base = max по `CRLNumber`. Delta = применимая
  (`baseCRLNumber ≤ base.CRLNumber < delta.CRLNumber`) с max `CRLNumber`.
- Итог = base ∪ delta, delta авторитетна для изменений после base:
  запись про серийник отзывает (любой reason кроме `removeFromCRL`) либо
  снимает отзыв (`removeFromCRL` → ACTIVE).
- `CrlStatus.fresh` теперь берётся от применённой delta (иначе от base) —
  делает fallback свежее (~7.5ч вместо ~27ч) и, главное, честно ловит
  досрочные отзывы из delta.
- `CRLNumber`/`BaseCRLNumber` парсятся через BC (`ASN1Integer` внутри
  `getExtensionValue`-OCTET STRING). `verify()` перешёл с `crl.isRevoked`
  на `crl.getRevokedCertificate` (нужно инспектировать reason для
  removeFromCRL) — **грабли в тестах**: relaxed MockK для platform-типа
  `X509CRLEntry` возвращает не-null дочерний мок, поэтому «не отозван»
  в тестах надо стабить как `getRevokedCertificate(any()) returns null`,
  а не `isRevoked returns false`.
- Загрузка delta не изменилась (по-прежнему per-endpoint скачивание;
  merge — только на этапе verify).

Консервативность при кривой delta: repo-фикстуры тест-PKI содержат delta
с `CRLNumber`=10 при `baseCRLNumber`=14 (delta старше своего base) — не
применима (`14 < 10` = false), безопасно игнорируется, работаем на full.
Поэтому live-интеграционные тесты не изменились (тест-pack cert'ы всё равно
не отзываются через CRL — только OCSP, quirk #21).

Покрытие: `CrlServiceTest` +4 кейса (delta отзывает; removeFromCRL снимает;
неприменимая delta игнорируется; freshness от delta). Тесты 219 → **223**,
coverage 76% → **77%**.

### 31. `ca.crl.url` = root-issued CRL промежуточного (его CRL DP), не его собственный CRL
Аудит адресов PKI (сверка с `test.pki.gov.kz` / реестром `root.gov.kz/registr/`
+ разбор `cRLDistributionPoints` самих сертов) показал рассинхрон `ca.crl.url`
с реальностью. Ключевое различие:
- **Собственный CRL промежуточного** (напр. `crl.pki.gov.kz/nca_gost_2022.crl`,
  `test.pki.gov.kz/crl/nca_gost2022_test.crl`) — выпущен *самим* промежуточным,
  перечисляет отозванные **end-entity**. Это для `crl.url` (проверка листовых).
- **CRL для проверки *самого* промежуточного** — выпущен **корнем** и лежит по
  его `cRLDistributionPoints`. Это для `ca.crl.url`.

Реальные DP промежуточных (источник истины — RFC 5280 §4.2.1.13):
| Промежуточный | CRL DP (root-issued) |
|---|---|
| `nca_gost.crt` | `crl.root.gov.kz/gost.crl` |
| `nca_rsa.crt` | `crl.root.gov.kz/rsa.crl` |
| `nca_gost_2022.cer` | `crl.root.gov.kz/gost2015_2022.crl` |
| `nca_rsa_2022.cer` | `crl.root.gov.kz/rsa2020.crl` |
| `nca_gost2022_test.cer` (TEST) | `crl.root.gov.kz/gost_test_2022.crl` |

Самоподписанные корни (`root_*`) **CRL DP не имеют — и правильно**: trust anchor
не отзывают через CRL. `caCrlService.verify(root)` → нет CRL издателя → UNAVAILABLE
→ не REVOKED → безвредно.

Фиксы (вариант «конфиги актуальны»):
- **prod** `application.yml`: `gost2020.crl` (ничей DP в дефолтном бандле) →
  `gost2015_2022.crl` (реальный DP `nca_gost_2022`). Было последствием quirk #25:
  бандл догнал 2022-иерархию, а `ca.crl.url` — нет.
- **test** `application-test.yml`: `test.pki.gov.kz/.../nca_gost2022_test.crl`
  (собственный CRL промежуточного — issuer не совпадёт при проверке промежуточного,
  отфильтровывался) → `crl.root.gov.kz/gost_test_2022.crl`.

Почему это не было фатально до фикса: `CaService.updateCache` (строка ~105)
дёргает `caCrlService.verify(caCert)` для **каждого** серта бандла, а `verify()`
вызывает `fetchOnDemandCrls` — тянет CRL из `cRLDistributionPoints` **самого
серта** on-demand. Т.е. корректный root-issued CRL приходил и так; `ca.crl.url`
— лишь pre-warm-список, который дрейфовал. Отсюда следствие: `crl.root.gov.kz`
— живая зависимость и в тестах (через on-demand при загрузке CA-бандла), правки
конфига новых хостов не добавили.

### 32. Аудит кода (P0/P1): гонка CA, HTTP-статусы, SSRF strict-режим
Многоагентный аудит (5 областей) + верификация → отчёт/план в
`code-audit-plan.md` (рабочий артефакт v4, **не** для upstream). Крипто-ядро
признано корректным (подделка не проходит); баги — в сторону «ложный отказ /
неверный HTTP-код / 500». Закрыты P0 (корректность) + P1 (безопасность):

**P0:**
- **Гонка `CaService`** (H1): геттер `rootCertificates` отдавал живой
  `mutableList`, который `updateCache` мутировал `clear()+addAll()` — lock-free
  читатель ловил CME либо транзиентно пустой список → issuer=null → ложный
  `valid:false`. Фикс: `@Volatile var certificates: List` + атомарная замена
  снапшота + `certificatesLock`; геттер lock-free. `CaServiceConcurrencyTest`.
- **HTTP-статусы** (H2/H3/M1/M6/M7): advice ловил `HttpMessageNotReadableException`
  (RuntimeException) → битый JSON давал 500; `MethodArgumentNotValidException`
  (не RuntimeException) шёл мимо `ErrorResponse`. Фикс: специфичные хендлеры
  (parse/validation→400 с полями), catch-all на `RuntimeException` (НЕ
  `Exception` — иначе съесть 405/415), обобщённый message. Единая политика
  исключений: guard `catch(ApplicationException){throw e}` в одиночных
  verify/sign (Cms/Pdf/Jwt/Wsse) — раньше свой же 400 глотался в 500;
  `KalkanWrapper.tryReadKey`: `KeyException→ClientException` (плохой пароль p12 =
  400, quirk #22); `CmsService.verify` таксономия (битый CMS→400, внутренние→500).
- **XML DOM** (M2/M3): `clearSignatures`/`verify` — снимок узлов +
  `parentNode.removeChild` (было: live NodeList → 500 на ≥2/вложенных подписях).
- **Валидация** (M4/M5): `PdfSigner.signer` `@NotNull @Valid` nullable (было
  `lateinit`→500); `@Valid`-каскад на 8 sign/info DTO.

**P1 (security):**
- **SSRF** (M9): URL берутся ИЗ серта (OCSP AIA — priority, CRL DP — on-demand),
  фильтр был только по схеме. Решение (согласовано): **strict-режим**
  `NCANODE_OCSP_STRICT`/`NCANODE_CRL_STRICT` (default false) — только конфиг-URL,
  игнор cert-URL. **Плюс** минимальный host-block `isInternalHost` в default:
  loopback/link-local(169.254 cloud-metadata)/any-local отсекаются для cert-URL;
  RFC1918 НЕ блокируется (легит. внутренний PKI — для него strict). Оба CRL-конфига
  на один `NCANODE_CRL_STRICT`. Синергия с quirk #31: strict не теряет покрытие
  НУЦ (всё в конфиге).
- **OCSP CertID** (RFC 6960 §3.2): сверка `singleResp.certID.serialNumber` с
  запрошенным — responder не может подсунуть статус чужого серийника в [0].
- **crlList/ocspUrls**: broaden `catch(Exception)` — крафт-серт с URI-тегом не
  на IA5String (`DERIA5String.getInstance`→`IllegalArgumentException`) больше не
  даёт 500, просто нет URL.
- **revocationCheck default**: оставлен opt-in (upstream-совместимость), но
  `warnIfRevocationDisabled` пишет WARN в 6 verify-методах, когда отзыв не
  запрошен (отозванный серт молча проходит — оператор должен видеть).

Грабли аудита: (1) M1 (`KeyException→ClientException`) сам по себе даёт 400 для
плохого пароля (verify-методы без catch отдают ClientException в advice); мог бы
регрессировать Jwt/Wsse (полагались на `catch(KeyException)`), но они на
single-overload `read` — не задеты. (2) 2 теста кодировали старое 500-поведение
плохого пароля — обновлены на 400. (3) OCSP serial-check валидируется живой
интеграцией (ответы test.pki.gov.kz имеют совпадающий serial).

**P2 (ресурсы):** `CertificateWrapper.fromFile` — `FileInputStream.use{}` (был
FD-leak); удалена `AsyncConfiguration` (@Async нигде не использовался, executor
неинициализирован); `effectiveUserAgent` — версия из `BuildProperties` (был
"NCANode/dev", т.к. `implementationVersion` = null в boot-jar).

**P3 (качество, частично):** удалено ~400+ строк мёртвого кода — пакет `oid/`
(336, 0 ссылок), `TspService.info`, `fromBase64`, `findAllUrls`,
`CertificateGender/gender`. `HttpClientConfiguration.requestBuilder(uri)` делает
инвариант quirk #24 (непустой UA) структурным (4 сервиса). Тяжёлые рефакторы
(mapPartial на 15 batch, generateSignedCms, god-методы) осознанно отложены как
отдельный `refactor:`-заход — чистое behavior-preserving изменение с
regression-поверхностью, нечего мешать с багфиксами. См. `code-audit-plan.md`.

**P4 (тесты):** crypto-негативы для JWT/CMS/XML (tamper/чужой cert → verify
отвергает — раньше прошли бы при полностью сломанной проверке подписи);
`revocations[].result == REVOKED` (контракт quirk #28); `KeyStoreWrapperTest` —
реальный sign/verify пары ключей вместо тавтологии; ⏰ дедлайн 2027-05-07
задокументирован. Суть **233**, coverage 76%.

### 33. Kotest 6 (миграция с 5.9, июль 2026): три граблины
- **Координаты spring-extension**: в Kotest 6 он вернулся в основной monorepo —
  `io.kotest:kotest-extensions-spring` с версией, ВЫРОВНЕННОЙ с ядром (в
  каталоге один `version.ref = "kotest"` на оба — Dependabot бампит синхронно,
  рассинхрон невозможен). Старые координаты `io.kotest.extensions:...`
  застряли на 1.3.0 (Kotest 5-only): с ядром 6.x роняют discovery —
  `NoSuchMethodError: SpecRef$Reference.<init>`, ни один тест не стартует.
- **`SpringExtension` теперь класс, не object** → везде `SpringExtension()`.
- **Constructor injection требует project-level регистрации**: спеки с
  `@param:Autowired` в primary constructor инстанцируются ЧЕРЕЗ
  ConstructorExtension, а регистрация `extension(...)` в теле спека опаздывает
  → `SpecInstantiationException`/`IllegalArgumentException (instantiate.kt)`.
  В Kotest 6 classpath-scanning и `@ApplyExtension` удалены — единственный
  путь: `io.kotest.provided.ProjectConfig` (FQN-конвенция) с
  `override val extensions = listOf(SpringExtension())`. Глобальный
  SpringExtension безвреден для не-Spring спеков (все 233 зелёные).

### 34. CRL хранится как mmap-индекс, а не как распарсенный X509CRL
Мотивация: жалоба на 700 МБ RSS на простое. Замер (`jcmd VM.native_memory`,
`vmmap`) показал, что живой heap — 265 МБ, и **260 МБ из них — один
распарсенный CRL**. `sun.security.x509.X509CRLImpl` держит каждую запись
отдельным объектом: боевой `nca_gost_2022.crl` (20.8 МБ, 422 065 записей)
занимает **243 МБ кучи — 604 байта на запись**. Прежний `crlMemCache` держал
это strong-ссылкой навсегда и грел на старте, т.е. один CRL составлял
практически весь heap сервиса.

Решение — `kz.ncanode.crl`:
- **`Der`** — минимальный DER-ридер поверх `ByteBuffer` (отвергает BER
  indefinite-length, многобайтовые теги, длину >4 байт; каждое чтение
  проверяется по границам буфера).
- **`CrlScanner`** — потоковый обход `CertificateList` без материализации
  записей: метаданные + диапазон байт `tbsCertList` + колбэк на запись
  (серийник отдаётся как диапазон в буфере, `ByteArray` на запись не создаётся).
- **`CrlIndex`** — плоский файл-спутник `<имя>.crl.idx`: отсортированная
  таблица серийников фиксированного шага + параллельные массивы дат и
  причин, `mmap` + двоичный поиск.

Замеры на боевом CRL: индекс **11.4 МБ** против 243 МБ, построение **524 мс**
против 1.16 с у `CertificateFactory` (в 4 раза быстрее — не строятся объекты),
пик кучи при обходе — 7.6 МБ (проверено под `-Xmx24m`).

Почему mmap, а не heap-массивы и не H2 (обсуждалось): страницы file-backed —
не считаются в `-Xmx`, вытесняются ОС под давлением, переживают рестарт
(прогрев после первого запуска сводится к `mmap`, парсинг не повторяется).
H2 отвергнут по цифрам: дефолтный `CACHE_SIZE` 64 МБ на базу — больше, чем
весь индекс, плюс JDBC, batch-insert сотен тысяч строк на каждое обновление
CRL и повреждённая база как новый режим отказа.

Грабли и решения:
- **Подпись проверяется вручную**, раз `X509CRL` больше нет: хэшируется
  диапазон `tbsCertList` прямо в отображённом файле. Алгоритм берётся по OID
  из самого CRL — `Signature.getInstance("1.2.398.3.10.1.1.2.3.2")` работает,
  Kalkan регистрирует GOST-OID'ы как имена алгоритмов, JDK — RSA'шные.
  **Форма `OID.<...>` не годится** — её GOST-провайдер не знает (RSA-провайдер
  знает, поэтому ошибка проявилась бы только на GOST).
- **Отрицательные серийники в записях отбрасываются** (RFC 5280 §4.1.2.2
  требует положительный). Иначе беззнаковая интерпретация такого серийника
  могла бы совпасть с серийником настоящего сертификата → ложный REVOKED.
- **Indirect CRL** (`certificateIssuer` 2.5.29.29 у записи) и непонятые
  critical-расширения записи помечают весь индекс `unusableReason`, и
  `CrlService` его пропускает: мы сопоставляем записи только по серийнику,
  а в indirect CRL запись принадлежит другому издателю.
- **Инвалидация** — по длине и mtime исходного `.crl`; битый/устаревший/чужой
  версии индекс молча перестраивается. Orphan-очистка индексов добавлена в
  `updateCache` рядом с очисткой самих CRL.
- **`NCANODE_CRL_CACHE_ENABLED=false`** теперь означает «переоткрывать индекс
  на каждый verify» (mmap + чтение заголовка), а не «парсить CRL заново».

Страховка от собственного разбора ASN.1 — `CrlIndexTest`: каждая из 54 записей
реального `nca_gost2022_test.crl` сверяется с тем, что о ней говорит JDK
(серийник, дата, причина), плюс метаданные, GOST-подпись реальным ключом CA,
переиспользование и перестроение sidecar'а, битый индекс, не-CRL, обрезанный
DER. Валидация на проде: warmup проверил подписи 7 реальных CRL НУЦ
(GOST + RSA, включая 19.5-МБ) через новый путь.

### 35. JVM-настройки в Dockerfile не применялись вообще
`ENV JAVA_OPTS='-Xms128m -Xmx512m'` при `ENTRYPOINT ["java", "-jar", ...]` —
exec-форма `$JAVA_OPTS` не разворачивает, переменная нигде больше не
упоминалась. JVM брала дефолт в 25% памяти хоста: reserved heap 8 ГБ,
committed 1.63 ГБ, нативные структуры G1 — 90 МБ. Починено shell-формой с
`exec` (с прокидыванием `"$@"`, чтобы аргументы контейнера не терялись).

Дефолты подобраны под замеренный профиль: `-Xms64m -Xmx512m -XX:+UseSerialGC
-XX:MaxMetaspaceSize=256m -XX:MaxHeapFreeRatio=30 -XX:MinHeapFreeRatio=10
-XX:+ExitOnOutOfMemoryError`. SerialGC здесь не компромисс, а выигрыш: на
такой куче нативные структуры G1 (90 МБ → 57 МБ после фикса CRL) сжимаются
до **0.26 МБ**, а `*HeapFreeRatio` отдаёт неиспользуемое обратно ОС.
`-Xmx512m` — потолок с запасом на подпись объёмных документов; при живом
heap'е в 30 МБ он не занимается.

В docker-compose.yml добавлен лимит 768 МБ — в форме
`deploy.resources.limits.memory`, а НЕ `mem_limit`: последней нет в схеме
Compose v3, и IDE подсвечивает её как ошибку («Key 'mem_limit' is not expected
here»), хотя рантайм её понимает. Обе формы дают одинаковый результат
(проверено: `HostConfig.Memory` = 805306368 при `docker compose up` вне swarm).
Заодно убран ключ `version: '3.7'` — Docker Compose V2 сам просит его удалить
(«the attribute `version` is obsolete»), и именно он заставлял IDE проверять
файл по устаревшей схеме.

Итог по замерам (одна и та же машина, приложение на простое после прогрева):

| | было | индекс | индекс + флаги |
|---|---|---|---|
| живой heap после full GC | 265 МБ | 29.5 МБ | 28.7 МБ |
| Java heap committed | 1.63 ГБ | 110 МБ | 65.6 МБ |
| нативные структуры GC | 90 МБ | 56.8 МБ | 0.26 МБ |
| NMT total committed | 1.84 ГБ | 288 МБ | **186 МБ** |
| physical footprint | ~650 МБ | 259 МБ | **246 МБ** |

Оставшееся — базовая стоимость Spring: metaspace 51 МБ, code 22 МБ,
symbol 12 МБ, class 9 МБ, threads 3.8 МБ.

### 36. Потолок размера CRL и LRU для on-demand кэша
Продолжение quirk #32 (SSRF): в нестрогом режиме (дефолт) адрес CRL берётся из
`cRLDistributionPoints` присланного сертификата. Фильтровались только схема и
внутренние хосты — ни размер закачки, ни число накопленных файлов ограничены
не были. Сертификат с CRL DP на большой файл заставлял сервер скачать его
целиком, а каждый новый URL добавлял файл в `ondemand` навсегда.

**Потолок размера** (`NCANODE_CRL_MAX_SIZE_MB`, дефолт 64):
- `download` переведён с `BodyHandlers.ofFile` на `ofInputStream` + своё
  копирование буфером. `ofFile` принял бы файл любого размера — оборвать
  загрузку он не даёт. Память при этом не растёт: буфер 64 КБ.
- Если сервер прислал `Content-Length` больше потолка — отказ до чтения тела.
  Иначе счётчик проверяется перед записью каждого блока, так что за потолок
  на диск не попадает ничего, а `finally` убирает `.tmp`.
- 64 МБ — примерно трёхкратный запас к боевому `nca_gost_2022.crl` (~20 МБ).
  Потолок общий для конфиг-CRL и on-demand: разделять смысла нет, а рост
  боевого CRL сверх 64 МБ должен быть виден как явная ошибка, а не как
  молчаливое отключение проверки отзыва. `0` снимает ограничение.

**LRU on-demand** (`NCANODE_CRL_ONDEMAND_MAX`, дефолт 64):
- «Реже всего использованный» = по последнему успешному применению в `verify`
  (`onDemandLastUse`, epoch millis); для файлов, ни разу не пригодившихся в
  этом процессе (в т.ч. после рестарта) — по `lastModified`, т.е. по времени
  загрузки. Шкала одна, значения сравнимы напрямую: `max(recordedUse, mtime)`.
- Отмечается именно **пригодившийся** CRL (`loadUsableCrl` вернул не-null),
  а не просто просмотренный: скачанный по DP чужого сертификата и никому не
  подошедший уходит первым.
- Вытесняется вместе с файлом-спутником `.crl.idx` и записями in-memory кэша.
- Вызывается после on-demand загрузок и из `updateCache` (периодическая
  уборка) — иначе на инстансе, который перестал получать новые DP, уже
  разросшийся кэш не ужался бы никогда.
- `crlMemCache` заодно переведён с `ConcurrentHashMap` на синхронизированный
  access-order `LinkedHashMap` с потолком 256 записей. Порядок доступа
  мутируется на чтении, поэтому синхронизация нужна на всей карте.

### 37. Потолок ответа для OCSP / TSP / CA — `HttpClientConfiguration.sendBounded`
Тот же класс проблемы, что quirk #36, но другой транспорт: все три сервиса
читали ответ через `BodyHandlers.ofByteArray()` без ограничения — сразу в
кучу, а не на диск. Для OCSP это к тому же управляется извне: в нестрогом
режиме адрес респондера берётся из AIA проверяемого сертификата.

Реализация — `sendBounded(client, request)` рядом с `requestBuilder` в
`HttpClientConfiguration`: инвариант становится структурным, как и с непустым
User-Agent (quirk #24). Тело читается потоково с проверкой счётчика перед
каждым блоком; объявленный `Content-Length` сверх потолка отвергается до
чтения тела. Потолок — `NCANODE_HTTP_CLIENT_MAX_RESPONSE_KB`, дефолт 1024 КБ
(OCSP/TSP/CA-обмены — единицы килобайт, запас в десятки раз). Возвращает
`BoundedResponse(statusCode, body)`.

**Проверено экспериментом (важно и для quirk #36):** переход с
`ofByteArray`/`ofFile` на `ofInputStream` НЕ ломает `HttpRequest.timeout()`.
Хотя `send` возвращается по заголовкам (замерено: 0.0 с), JDK всё равно
обрывает обмен по таймауту запроса — заблокированный `read` получает
`IOException: closed` с корневой причиной `HttpTimeoutException: request timed
out` ровно на 3-й секунде при `timeout(3s)`. То есть медленный сервер не может
держать поток вечно, slow-loris не появился ни здесь, ни в CRL-загрузке.

`ResponseTooLargeException` наследует `IOException` намеренно: все три сервиса
уже ловят его и переводят в свои отказы. Для OCSP это UNAVAILABLE, а не
UNKNOWN — по разделению quirk #28 пригодного ответа не было, значит fallback
на свежий CRL допустим.

`CaService.download` переведён туда же (сверх изначально запрошенного объёма —
это тот же вызов): попутно пустое тело больше не превращается в пустой файл на
диске. Итоговое поведение то же — `downloadCert` вернёт null и `checkCertForNull`
остановит приложение, — но без порчи кэша.
### 38. AdES-уровни: три вещи, которые стоили времени
Полная картина — `ades-levels-plan.md`. Здесь то, что можно наступить снова.

- **`/xml/verify` не проверял НИ ОДНУ XAdES-подпись** — и это баг старого
  эндпойнта, а не новых. `Id` на `xades:SignedProperties` не регистрировался
  как ID-атрибут, ссылка `#...` не резолвилась. Фикс — `registerXadesIds`
  в конструкторе `XMLSignatureWrapper`, то есть чинится для всех потребителей
  сразу. Та же причина всплыла второй раз в `XadesInspector`, когда
  `XMLSignature` строился напрямую в обход обёртки: **любой разбор
  XML-подписи должен идти через `XMLSignatureWrapper`.**
- **Выбор данных об отзыве — по покрытию момента, а не «вшитый первичен»**
  (RFC 6960 §2.2, RFC 5280 §5.1.2.4–5.1.2.5, §6.1). `CrlService.statusOf` /
  `OcspService.statusOf` — чистые функции вердикта над переданным материалом,
  без сети; непокрывающий момент ACTIVE понижается до UNAVAILABLE, REVOKED
  сохраняется. `CertificateWrapper.isValid` **не менялся** — он и раньше
  оценивал прикреплённые статусы, различаются только их поставщики. Отсюда
  же совместимость со старыми эндпойнтами: живой путь не тронут.
- **`level` ≠ `verifiedLevel`.** Первое — что подпись о себе заявляет, второе
  — до чего проверка её подтвердила. Заявленный LTA с непроверяемой меткой
  даёт `verifiedLevel: LT`; без запрошенной проверки отзыва уровень не
  поднимается выше T. Присутствие структуры — не доказательство.

**NCALayer не выпускает LT/LTA тестовыми ключами** — доверенные корни его
AdES-часть берёт только из боевого набора, а B и T корней не требуют. Значит
эталоны выше T бывают только боевым ключом, а им в репозиторий нельзя
(реальные ИИН/ФИО): лежат локально, исключены через `.git/info/exclude`,
гоняются `AdesReferenceCompatibilityTest` под профилем `reference`
(боевые адреса).
Спека включается целиком только при наличии файлов — иначе `CaService`
тянул бы боевой бандл на каждом прогоне CI. Прогон: **15/15 проходят**.

Мелочь, но повторяемая: Kalkan — форк старого BC, геттеры `getDERObject()` /
`getDEREncoded()` из Kotlin через property-access (`.dERObject`) НЕ
разрешаются; и путь вида `/cms/*` внутри KDoc открывает вложенный комментарий
(«Unclosed comment»).

### 39. `@Valid` на списках: `List<@Valid X>` + флаг компилятора
Hibernate Validator ругается на `@Valid` над самим списком (HV000271,
устаревшая форма) и требует аннотацию на аргументе типа. Но Kotlin **не пишет
аннотации аргументов типа в байткод** без `-Xemit-jvm-type-annotations` — с
переносом и без флага каскад молча перестаёт работать, и вложенный объект
проходит без валидации (`ExceptionHandlingMvcTest` это ловит: 500 вместо 400).
Флаг добавлен в `build.gradle.kts`, все DTO переведены на `List<@Valid X>`.

### 40. `/DocTimeStamp` проверяется как метка, а не как подпись
`PdfService.verify` перебирает `document.signatureDictionaries`, куда попадают
и документные метки времени. Раньше метка шла общим CMS-путём и падала с
`content hash found in signed attributes different`: в её `/Contents` лежит
токен RFC 3161, чьи подписанные атрибуты описывают TSTInfo, а не байты
`/ByteRange`. Следствия были два: ERROR в логах на каждую проверку LTA-PDF и
`valid=false` от `/pdf/verify` для совершенно валидного документа (метка
считалась недействительной подписью). Теперь метка проверяется через
`TspService.verify`, а в `PdfSignerInfo` есть флаг `documentTimestamp`.
`PadesService` берёт вердикт по меткам оттуда же — второй разбор документа
не нужен.

### 41. `NoClassDefFoundError: ThrowableProxy` при Ctrl+C
Симптом: при остановке приложения из терминала иногда падает
`Exception in thread "SpringApplicationShutdownHook"
java.lang.NoClassDefFoundError: ch/qos/logback/classic/spi/ThrowableProxy`.

Механика: logback подгружает классы печати стек-трейсов **лениво** — только
когда впервые логируется исключение (проверено `-verbose:class`: за обычный
прогон `ThrowableProxy` не загружается вовсе, только конвертеры). Если первым
таким случаем оказывается остановка — Ctrl+C прерывает фоновую загрузку CRL,
та логирует ошибку — классы уже неоткуда взять: hook'и завершения работают
параллельно, и загрузчик boot-jar'а успевает закрыться. Для приложения
безобидно (оно и так завершается), но выглядит как падение.

Закрыто с двух сторон: `NCANode.main` заранее трогает четыре класса logback
(`preloadThrowableLogging`), а `CrlWarmupService` не печатает стек-трейс,
когда причина — прерывание потока. Первое проверяемо: с фиксом
`ch.qos.logback.classic.spi.ThrowableProxy` появляется в `-verbose:class` на
старте, без фикса — не появляется.

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

### 0. Довести `feature/ades-levels` (текущая задача)

Совместимость проверена в обе стороны: эталоны NCALayer мы принимаем (15/15,
`AdesReferenceCompatibilityTest`), наши подписи его валидатор принимает
(14/14 вручную, «Подтверждённый уровень» совпал с нашим `verifiedLevel` на
каждом файле). Документация и `openapi.yml` обновлены. PR — mitwork/NCANode#12.

Осталось необязательное:

1. Коммитабельные эталоны — генератором на библиотеке НУЦ с тестовыми корнями,
   если понадобится покрытие совместимости в CI (сейчас оба направления
   проверены вручную и на боевом ключе, поэтому в CI не живут).
2. Detached CAdES в их валидаторе — единственный не прогнанный вручную случай;
   как его туда скормить, описано в `ades-levels-plan.md`.

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

10. **AdES-уровни** (ветка `feature/ades-levels`): CAdES/XAdES/PAdES
    уровней B/T/LT/LTA под обновлённый NCALayer, Kalkan 0.7.5 → 0.7.8,
    сверка на эталонах НУЦ, batch для трёх новых семейств.
    Тесты 233 → **330**, coverage 76% → **85%**. См. `ades-levels-plan.md`.

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
