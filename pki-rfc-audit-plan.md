# PKI RFC-compliance — план работ

Источник: `pki-rfc-audit-report.md` (multi-agent аудит, 12 подтверждённых
находок из 35, 23 отсеяны верификаторами). Корневая причина всех HIGH —
`VerificationResponse` отдаёт плоский `valid`, не сообщая, **что именно**
покрыто подписью.

Легенда статуса: ⬜ TODO · 🔶 в работе · ✅ сделано · ⏸️ отложено (с обоснованием)

**Итог ремедиации:** все HIGH/MEDIUM (пункты 1–2) + значимые LOW (пункт 3)
закрыты. Пункт 4 — осознанно отложен (см. ниже). Сьют 203/0, zero warnings.

## Пункт 1 — verification-contract в CMS + OCSP responder ✅ ГОТОВО

| # | Sev | Находка | Где | Статус |
|---|---|---|---|---|
| 1.1 | HIGH | CMS с 0 подписантов → `valid=true` | `CmsService.kt:241-247` | ✅ |
| 1.2 | HIGH | Подписант без cert в store → молча ОК (подпись не проверена) | `CmsService.kt:303-313` | ✅ |
| 1.3 | MED | Cert делегированного OCSP-responder'а не проверен на validity | `OcspService.kt:275-300` | ✅ |

Фиксы: guard на пустой `signerInfos` (return valid=false) + guard `certs.isEmpty()`
per-signer; в OCSP — `checkValidity(producedAt)` + учёт `id-pkix-ocsp-nocheck`.
Тесты: 2 в `CmsServiceIntegrationTest` (zero-signers, cert-stripped). Сьют 192/0.

## Пункт 2 — покрытие документа подписью ✅ ГОТОВО

| # | Sev | Находка | Где | Статус |
|---|---|---|---|---|
| 2.1 | HIGH | XML-DSig не проверяет, что Reference покрывает документ (XSW) | `XMLSignatureWrapper.coversWholeDocument`, `XmlService.kt` | ✅ |
| 2.2 | HIGH | PDF не проверяет `/ByteRange` на весь файл (PAdES incremental-update) | `PdfService.signatureCoversWholeDocument` | ✅ |
| 2.3 | MED | WSSE не проверяет, что подпись покрывает SOAP Body (move-original XSW) | `WsseService.signatureReferencesId` | ✅ |

Фиксы:
- **2.1** — `coversWholeDocument()`: требуем Reference с пустым URI + только
  безопасные transforms (enveloped + c14n); иначе XSW. `PdfSignerInfo`-аналога нет,
  встроено в `XmlService.verify`.
- **2.2** — `signatureCoversWholeDocument()`: `/ByteRange` от 0 до EOF; на уровне
  документа требуем, чтобы хотя бы одна подпись покрывала весь файл (multi-sign
  safe). Новый флаг `PdfSignerInfo.coversWholeDocument`.
- **2.3** — регистрируем `wsu:Id` ровно на настоящем Body + `secureValidation=true`
  + явная проверка, что Reference ссылается на body id; per-signature try/catch
  (битая подпись → valid=false, не 500).

Тесты: +2 PDF (forgery + whole-doc), +2 XML (coversWholeDocument: ""/`#x`),
+1 WSSE (broken body binding). Сьют 192 → **197**.

## Пункт 3 — LOW conformance ✅ ГОТОВО

| # | Находка | Где | Статус |
|---|---|---|---|
| 3.1 | TSA EKU: criticality + sole-EKU (RFC 3161 §2.3) | `TspService.verify` | ✅ |
| 3.2 | NPE на cert без keyUsage extension (RFC 5280 §4.2.1.3) | `CertificateKeyUsage.fromKeyUsageBits` | ✅ |
| 3.3 | Unrecognized critical extensions (cert) не reject'ятся (§4.2) | `CertificateWrapper.isValid` | ✅ |
| 3.4 | Unrecognized critical extensions (CRL) не reject'ятся (§5.2) | `CrlService.verify` | ✅ |

Фиксы:
- **3.2** — `fromKeyUsageBits(BooleanArray?)`: `null`/короткий массив → UNKNOWN.
- **3.1** — строго: id-kp-timeStamping ЕДИНСТВЕННЫЙ EKU + помечен critical.
  Эмпирически: NCA GOST TSA конформен (`TsaCertDiagnosticTest` стережёт это).
- **3.3** — НЕ `hasUnsupportedCriticalExtension()` (Kalkan/BC ложно браковал
  critical EKU!), а явный allowlist {keyUsage, basicConstraints, EKU, SAN,
  certPolicies}; critical вне набора → reject.
- **3.4** — любой critical-extension в CRL → skip (мы не обрабатываем ни одно).

⚠️ **Ключевой урок**: `X509Certificate/X509CRL.hasUnsupportedCriticalExtension()`
в Kalkan/BC считает critical extendedKeyUsage «неподдержанным» → отвергал
конформный TSA-cert и валил CAdES-T. Поэтому только явные allowlist'ы по OID.

Тесты: +4 `CertificateKeyUsageTest`, +1 `CrlServiceTest` (IDP-critical skip),
+1 `TsaCertDiagnosticTest` (NCA TSA conformance guard). Сьют 197 → **203**.

## Пункт 4 — редизайн через JDK PKIX ⏸️ ОТЛОЖЕНО

**Решение (2026-06): не делаем сейчас.** Это не точечный фикс, а архитектурный
редизайн с высоким риском регрессии и LOW-выгодой. Оформлено как осознанный
технический долг.

### Что закрыл бы

Прогон trust-решения через JDK `CertPathValidator` / `PKIXParameters` +
`PKIXRevocationChecker` (CA-bundle как TrustAnchors) разом закрыл бы две
оставшиеся **LOW** находки аудита:

| # | Sev | Находка | Где |
|---|---|---|---|
| 4.1 | LOW | RFC 5280 §6 path validation не реализован: цепочка не проверяет basicConstraints CA:TRUE / pathLenConstraint / nameConstraints на всех уровнях | `CertificateWrapper.isValid`, `CaService` |
| 4.2 | LOW | Revocation промежуточных/issuer CA не проверяется per-request (только дата) | `CertificateWrapper.isValid`, `CertificateService.attachValidationData` |

(Critical-ext rejection, которое раньше тоже сюда относили, уже закрыто
точечно в пункте 3 — для него редизайн не нужен.)

### Почему отложено

1. **Severity — LOW.** Аудит подтвердил: §6 не даёт реальной дыры, потому что
   `CaService.getRootCertificateFor` уже требует `cert.verify(root)` против
   **operator-pinned** CA-bundle — чужой/неизвестный intermediate подсунуть
   нельзя. Не хватает лишь обработки constraints, а не доверия как такового.
2. **Высокий риск регрессии на GOST.** Стандартный JDK `CertPathValidator`
   (`PKIX`) опирается на JCA-инфраструктуру алгоритмов. GOST 2015-цепочки НУЦ
   через Kalkan могут не пройти штатный PKIX-валидатор (algorithm constraints,
   `AlgorithmId`-маппинги, signature verify через провайдер) — легко получить
   ложный `valid:false` на полностью валидных подписях. Это переписывает
   рабочий, протестированный против live test.pki.gov.kz путь верификации.
3. **Стоимость >> выгода.** Переписать `CertificateWrapper.isValid` + `CaService`
   на PKIX, аккуратно вживив Kalkan-провайдер и сохранив текущую CAdES-T /
   темпоральную revocation-логику (#26) — большая работа ради двух LOW-пунктов
   без known-эксплойта.

### Триггер пересмотра

Браться стоит, только если появится конкретное требование:
- интеграция с PKI, где реально используются **nameConstraints / policyConstraints**
  на промежуточных CA (НУЦ РК сейчас их не применяет), **или**
- требование строгой проверки **отзыва промежуточных CA** на каждый запрос
  (сейчас покрыто частично через `CaService` CRL-кэш, decoupled от
  validation-time).

При заходе: делать инкрементально, с feature-flag, прогоняя весь
integration-сьют против live test.pki.gov.kz на каждом шаге; первым делом —
PoC, что GOST-цепочка НУЦ вообще проходит JDK `CertPathValidator` с Kalkan.
