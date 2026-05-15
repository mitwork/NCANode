# Test resources

Тестовые фикстуры для NCANode v4. Все артефакты из официального NCA SDK
("Keys and Certs" pack) — авторитетный источник тестовых cert'ов и
ключей с известными паролями. Парный test PKI находится на
`test.pki.gov.kz` (тестовые TSP/OCSP/CA/CRL endpoints).

Все ключи — GOST 2015. NCA полностью перешла на GOST 2015; RSA / GOST
2004 в коде поддерживаются по historic compat-причинам, но тестами не
покрываются (формат не выпускается с 2024).

## Catalog

### `ca/` — корневые тестовые сертификаты

```
root_test_gost_2022.cer    КУЦ РК тестовый (issuer для nca_gost2022_test)
nca_gost2022_test.cer      НУЦ РК тестовый (issuer для всех p12 ниже)
```

Скачать актуальные оригиналы: `http://test.pki.gov.kz/cert/{root_test_gost_2022,nca_gost2022_test}.cer`

### `crl/` — тестовые CRL'и

```
nca_gost2022_test.crl      базовый CRL для test-cert'ов
nca_gost2022_d_test.crl    delta CRL
```

Скачать оригиналы: `http://test.pki.gov.kz/crl/{nca_gost2022_test,nca_gost2022_d_test}.crl`

### `p12/` — тестовые ключи в PKCS#12

**Пароль для ВСЕХ ключей: `Qwerty12`**

Текущий период (`2026.05.08—2027.05.07`):

| Файл | Тип | Статус |
|---|---|---|
| `individual_valid.p12` | Физлицо | active |
| `individual_revoked.p12` | Физлицо | revoked |
| `legal_ceo_valid.p12` | Юрлицо — Первый руководитель | active |
| `legal_ceo_revoked.p12` | Юрлицо — Первый руководитель | revoked |
| `legal_employee_valid.p12` | Юрлицо — Сотрудник организации | active |
| `legal_employee_revoked.p12` | Юрлицо — Сотрудник организации | revoked |
| `legal_can_sign_valid.p12` | Юрлицо — Сотрудник с правом подписи | active |
| `legal_treasury_valid.p12` | Юрлицо — Казначейство-клиент | active |
| `legal_infosystem_valid.p12` | Юрлицо — Информационная система | active |

Истёкший период (`2024.10.29—2025.10.29`) — для тестов CAdES-T flow
"истёкший cert + валидная TSP метка":

```
expired_individual.p12     истёкший физлицо
expired_legal_ceo.p12      истёкший CEO юрлица
```

Источник: NCA SDK 2.0, `Keys and Certs/Gost2015/`.

### `cms/`, `xml/`, `wsse/`, `pdf/` — генерируются тестами

Пустые — наполняются генерацией внутри integration-тестов с использованием
ключей из `p12/`. Так оставляем чтобы не коммитить артефакты, чувствительные
к версии используемого signing-кода.

## Test PKI infrastructure (test.pki.gov.kz)

Интеграционные тесты используют официальную тестовую инфраструктуру НИТ
вместо моков. Конфигурация в `application-test.yml`:

```
NCANODE_CA_URL    http://test.pki.gov.kz/cert/root_test_gost_2022.cer
                  http://test.pki.gov.kz/cert/nca_gost2022_test.cer
NCANODE_CRL_URL   http://test.pki.gov.kz/crl/nca_gost2022_test.crl
NCANODE_OCSP_URL  http://test.pki.gov.kz/ocsp/
NCANODE_TSP_URL   http://test.pki.gov.kz/tsp/
```

Это даёт реальные OCSP-ответы (включая REVOKED для `*_revoked.p12`),
TSP-метки с правильной подписью TSA, и подписанные NCA CRL'и без
необходимости их мокать.
