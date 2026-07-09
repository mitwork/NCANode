# NCANode v4 — аудит кода и план работ

Рабочий артефакт v4 (**не** для upstream-PR). Составлен по результатам
многоагентного аудита (5 областей) + личной верификации HIGH/MEDIUM по коду.
Дата: 2026-07-09. Базовое состояние: после коммитов `2d0967e` (delta-CRL) /
`984d905` (prometheus).

## Вердикт

- **Качество кода:** хорошее (выше среднего). Долг — механическое дублирование
  + мёртвый пакет `oid/`.
- **Корректность:** крипто-ядро корректно (подделка не проходит: trust chain,
  XSW-защиты, ByteRange, TSP, OCSP-авторизация, delta-merge, XXE в
  DocumentWrapper — всё проверено). Реальные баги — в сторону «ложный отказ /
  неверный HTTP-код / 500», не forgery.

## Легенда статуса

- `[ ]` не начато · `[~]` в работе · `[x]` сделано
- Проверка: ✅ верифицировано лично по коду · ⚠️ по отчёту агента + паттерну

---

## Находки

### 🔴 HIGH — корректность

- **H1** `CaService.kt:90,165,170` ✅ — гонка: геттер `rootCertificates`
  отдаёт живой `mutableList`, `getRootCertificateFor` итерирует его без лока,
  пока `@Scheduled updateCache` делает `clear()+addAll()`. → CME/500 или
  транзиентно пустой список → `issuer=null` → ложный `valid:false`.
- **H2** `advice/ExceptionHandlerControllerAdvice.kt:15` ✅ —
  `@ExceptionHandler(RuntimeException)` ловит `HttpMessageNotReadableException`
  → битый JSON/enum-регистр/type-mismatch → 500 вместо 400.
  `MethodArgumentNotValidException` не ловится → 400 дефолтным Boot-телом мимо
  `ErrorResponse`.
- **H3** `CmsService.addSigners:136,191` (+`create`) ✅ — свой `ClientException`
  ловится своим же `catch(Exception)→ServerException` → 400 становится 500.
  Guard `catch(ApplicationException){throw e}` есть только в batch-методах.

### 🟠 MEDIUM

- **M1** `KalkanWrapper.tryReadKey:97` ✅ — неверный пароль p12/битый base64
  (`KeyException`) → `ServerException` 500, quirk #22 требует 400; рассинхрон
  с wsse/jwt/aliases (там 400).
- **M2** `XmlService.read:45-48` ✅ — `isClearSignatures` на XML с ≥2 подписями:
  фикс. граница `0 until length` + live NodeList → `item(i)=null` → 500 +
  удаление не тех узлов.
- **M3** `XmlService.verify:161,178` ✅ — `root.removeChild(signature)` падает
  на вложенной подписи → 500 вместо `valid=false`. Фикс:
  `signature.parentNode.removeChild`.
- **M4** `PdfSignRequest.kt:11,22` ✅ — `lateinit signer` + нет `@Valid` +
  невалидный `@NotEmpty` на объекте → запрос без `signer` → 500 вместо 400.
- **M5** DTO (`CmsCreateRequest`, `XmlSignRequest`, `Pkcs12*Request`, batch-и) ✅
  — нет `@Valid`-каскада на `signers`/`keys` → `key=""` → Kalkan → 500 вместо 400.
- **M6** `CmsService.create:64` ⚠️ — `data` nullable, `Base64.decode(data)` без
  null-check → NPE → 500 `message:null`.
- **M7** verify-эндпойнты ⚠️ — `cms/verify` внутренние сбои → 400;
  `xml/wsse/verify` клиентский вход → 500 (зеркально неверно).
- **M8** `CertificateWrapper.fromInputStream:277` ✅ — `fromFile` не закрывает
  `FileInputStream` → утечка FD (смягчается GC).
- **M9** `fetchOnDemandCrls`/`resolveOcspUrls` ✅ — blind SSRF: URL из CRL DP /
  OCSP AIA присланного серта, фильтр только по схеме, нет loopback/RFC1918.

### 🟡 LOW

benign-отзыв в fallback fail-closed (узко); OCSP CertID не сверяется с serial;
непроверенные ASN.1 при разборе URL серта → 500; advice не логирует 500;
`e.message` утекает мимо `detailedErrors`; batch без `@Size(max)` → DoS; CORS
открыт полностью; `AsyncConfiguration` отдаёт неинициализир. executor;
`effectiveUserAgent` в проде всегда `NCANode/dev`; XML/WSSE ищут подпись по
литеральному префиксу; WSSE SAAJ не захардён явно; `revocationCheck` default
пуст → отозванный проходит если не запрошено.

### Качество

Дубли: 15× batch try/catch; TSP-извлечение (Cms/Pdf); CMS-генерация
(create/addSigners/Pdf); HttpRequest-сборка (4 сервиса); revocation-флаги (24×);
orphan+stale (Crl/Ca); серии `catch(GeneralSecurityException-наследники)`.
Мёртвый код: `oid/` (336 строк, 0 ссылок, OID дублирован 3×); `TspService.info`,
`fromBase64`, `findAllUrls`, `CertificateGender/gender`. God-методы:
`CmsService.verify`(142), `CaService.updateCache`, `PdfService.verifySignature`.
Naming: методы `CertificateService` ≠ эндпойнты; `CmsBatchResponse`/
`CmsVerificationBatchResponse` вне конвенции.

### Тесты

Тавтологии: `TspServiceTest.info`, `KeyStoreWrapperTest` (`pub==pub`). Нет
crypto-негативов у JWT/CMS/XML. ⏰ 2027-05-07 истекают все `*_valid.p12`. Пробелы:
delta-merge (6 веток + подпись CRL не проверяется), `revocations[].result` (0
ассертов), HTTP/JSON-слой не поднимается.

---

## План работ (фазы по убыванию риска)

Оценка: S ≤ полдня · M ≈ день · L > дня.

### P0 — Корректность

- [x] **1. H1 гонка CaService** (S) — ✅ `@Volatile var certificates: List` +
  атомарная замена снапшота + `certificatesLock`; геттер lock-free быстрый путь.
  Тест `CaServiceConcurrencyTest` (8 читателей × 60 циклов writer'а). Суть 224.
- [x] **2. H2 advice** (M) — ✅ хендлеры `ApplicationException`/
  `HttpMessageNotReadableException`+`MethodArgumentNotValidException`(→400 с
  полями)/`RuntimeException`(catch-all, НЕ Exception — чтобы не съесть 405/415);
  `log.error` на 5xx; обобщённый message для непредвиденного. Тесты: unit (6) +
  `ExceptionHandlingMvcTest` (3, RANDOM_PORT: битый JSON/type-mismatch/пустой
  batch → 400).
- [x] **3. H3/M1/M6/M7 единая политика исключений** (M) — ✅ guard
  `catch(ApplicationException){throw e}` добавлен в `CmsService.create`/
  `addSigners`/`addSignersToCmsGenerator`, `PdfService.sign`, `JwtService.encode`,
  `WsseService.sign`; `KalkanWrapper.tryReadKey`: `KeyException→ClientException`
  (400); `CmsService.create`: null-check `data`→400; `CmsService.verify`:
  таксономия (CMSException/IllegalArgument→400, прочее→500). Verify-методы без
  catch (verifyCerts/xmlSign) отдают ClientException в advice сами. Обновлены
  2 теста, кодировавшие старое 500-поведение.
- [x] **4. M2/M3 XML DOM** (S) — ✅ снапшот `mapNotNull` +
  `node.parentNode?.removeChild` в `clearSignatures` и обоих `removeChild`
  в `verify`.
- [x] **5. M4/M5 валидация входа** (M) — ✅ `PdfSigner.signer`→
  `@NotNull @Valid var …? = null` + null-check в PdfService→400; `@Valid`-каскад
  на 8 DTO (Xml/Cms/Pkcs12 sign/info + batch). MVC-тест: пустой signer/PDF→400.
  Прим.: M1 уже давал 400 по статусу; каскад добавляет раннюю валидацию + чёткое
  сообщение с именем поля.

**P0 закрыт.** Суть 223 → **229** (concurrency + advice unit×2 + MVC×5), 0 падений,
coverage 76%. Правки только по коду/тестам; upstream-совместимость сохранена.

### P1 — Безопасность ✅ (обсуждено, согласовано, сделано)

- [x] **6. M9 SSRF** (M) — ✅ **strict-режим (allowlist), решение принято.**
  `NCANODE_OCSP_STRICT` / `NCANODE_CRL_STRICT` (default false): игнорировать
  URL из серта, использовать только конфиг. Плюс **минимальный host-block в
  default** (`isInternalHost` в Util): loopback/link-local(cloud-metadata)/
  any-local отсекаются для cert-derived URL; RFC1918 НЕ блокируется (легит.
  внутренний PKI — для него strict). `OcspService.resolveOcspUrls` (strict →
  config-only, non-strict → AIA с host-block), `CrlService.fetchOnDemandCrls`
  (strict → no-op, non-strict → host-block). Синергия с вариантом-2:
  strict не теряет покрытие НУЦ (все CRL/OCSP уже в конфиге). Тесты:
  `UtilTest.isInternalHost`, `CrlServiceTest` strict-skip.
- [x] **7. Мелочи безопасности** (S) — ✅ OCSP: сверка `CertID.serialNumber`
  ответа с запрошенным (RFC 6960 §3.2); `crlList`/`ocspUrls`: broaden catch
  (крафт-серт с не-IA5String URI → skip, не 500). **revocationCheck default
  (согласовано): оставлен opt-in + WARN** `warnIfRevocationDisabled` в 6
  verify-методах когда revocation не запрошен. CORS/`@Size(max)`/таймаут —
  отложены (не критичны, не в согласованном объёме P1).

### P2 — Ресурсы ✅

- [x] **8. M8 FD-leak** (S) — ✅ `FileInputStream(file).use { fromInputStream(it) }`.
- [x] **9. LOW** (S) — ✅ `AsyncConfiguration` **удалена** (@Async нигде не
  используется, executor был неинициализирован = спящий краш; @EnableScheduling
  в NCANode.kt не задет). `effectiveUserAgent` берёт версию из `BuildProperties`
  (опц. инъекция), а не из `implementationVersion` (null в boot-jar → был
  "NCANode/dev"); единый источник версии с MaintenanceService.

### P3 — Качество ✅ (основное; отдельный `refactor:` коммит после ремедиации)

- [x] **11. Мёртвый код** (S) — ✅ удалено ~400+ строк: `oid/` пакет (336,
  0 ссылок), `AsyncConfiguration` (dead+buggy), `TspService.info`,
  `fromBase64`, `findAllUrls`, `CertificateGender/gender` (+ 2 их теста).
  [в коммите ремедиации]
- [x] **10. Дедуп** (M) — ✅ `requestBuilder(uri)` (quirk #24 структурный);
  **`List.mapPartial`** (15 batch-методов, ~130 строк boilerplate убрано);
  computed `checkOcsp/checkCrl` на `VerifyRequest` (~13 сайтов, 9 файлов);
  `DirectoryService.deleteOrphans` (Crl/Ca); `catch(GeneralSecurityException)`
  collapse в `CertificateService` (6+3 catch → 2+2). Отложено (доп. мелочи):
  `generateSignedCms`, `extractTimestampToken` (Cms/Pdf TSP).
- [x] **12. God-методы** (M) — ✅ **`CmsService.verify`** 142 → ~40 строк +
  `parseCms`/`collectSignerCertificates`/`verifySigner` (логика построчно
  сохранена, CMS-интеграция зелёная). Отложено: `PdfService.verifySignature`.

Рефактор — отдельным коммитом поверх ремедиации (чистый behavior-preserving,
покрыт batch+integration тестами). Тесты 233, coverage 76% → **78%** (рефактор
убрал boilerplate — знаменатель уменьшился).

### P4 — Тесты ✅ (основное)

- [x] **13. Crypto-негативы** (M) — ✅ JWT (tamper payload + чужой cert →
  valid=false), XML (порча подписанного контента → valid=false), CMS (detached
  с чужими данными → отвергнут). Закрыт главный пробел ложной уверенности.
  Заодно убран мёртвый reflection + дедуп cert-extraction в JwtTest.
- [x] **14. HTTP-слой** (M) — ✅ в H2: `ExceptionHandlingMvcTest` (RANDOM_PORT:
  битый JSON / type-mismatch / пустой batch / @Valid-каскад → 400). Снапшот
  сериализации `StatusResponse` отложен (косвенно покрыт всеми integration).
- [~] **15. revocations + delta-merge** (M) — ✅ ассерт `revocations[].result
  == REVOKED` (контракт quirk #28). Отложено: 6 edge-веток delta-merge (merge
  покрыт 4 happy + strict).
- [x] **16. ⏰ 2027 expiry + тавтологии** (S) — ✅ дата `2027-05-07` + процедура
  ротации в CLAUDE.md; тавтологии убраны (`TspService.info` в P3;
  `KeyStoreWrapperTest` переписан на реальный sign/verify пары ключей).

**Итог: P0–P2 полностью, P3 частично (мёртвый код + requestBuilder; тяжёлые
рефакторы отложены), P4 основное. Тесты 223 → 233, coverage 76%.**

## Спорные (требуют согласования до реализации)

- **SSRF-политика (P1.6):** блокировать приватные IP по умолчанию (риск сломать
  интранет-CA) vs флаг-opt-in.
- **`revocationCheck` default:** оставить пустым (upstream-совместимость) vs
  сделать `[OCSP,CRL]` по умолчанию (breaking).
- **Судьба `oid/`:** подключить единым источником vs удалить.
