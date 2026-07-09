---
icon: fas fa-info-circle
---

## API

<div class="alert alert-info">

    Документацию по API можно посмотреть тут: <a href="https://v3.ncanode.kz/swagger-ui/">https://v3.ncanode.kz/swagger-ui/</a>

</div>

## Установка

Последнюю версию NCANode можно получить здесь:

[https://github.com/malikzh/NCANode/releases](https://github.com/malikzh/NCANode/releases)

## Запуск NCANode

Для запуска необходимо выполнить команду:

```bash
java -jar NCANode-3.0.0.jar
```

### Запуск в Docker

У NCANode есть образ в Docker Hub, и запустить его можно следующим образом:

```bash
docker volume create ncanode_cache
docker run -p 14579:14579 -v ncanode_cache:/app/cache -d malikzh/ncanode
```

## Настройки

В отличие, от версий 2.x, 1.x, теперь NCANode настраивается при помощи переменных окружения (os env).

Эти переменные окружения подставляются в конфигурацию в этом файле: [https://github.com/malikzh/NCANode/blob/master/src/main/resources/application.yml](https://github.com/malikzh/NCANode/blob/master/src/main/resources/application.yml)

### Список переменных окружения

* `NCANODE_PORT` - Порт (по умолчанию 14579)
* `NCANODE_DEBUG` - режим отладки (по умолчанию отключен)
* `NCANODE_CACHE_DIR` - путь к папке с кэшем (по умолчанию ./cache)
* `NCANODE_CRL_ENABLED` - поддержка CRL (по умолчанию включена)
* `NCANODE_CRL_TTL` - Время жизни CRL в кэше (по умолчанию 1440 минут)
* `NCANODE_CRL_URL` - URL'ы откуда скачивать списки CRL. По умолчанию они берутся из:
  * https://crl.pki.gov.kz/nca_gost_2022.crl
  * https://crl.pki.gov.kz/nca_rsa_2022.crl
* `NCANODE_CRL_DELTA_URL` - URL'ы дельта версий CRL. *Они обычно обновляются чаще чем основные*. По умолчанию:
  * https://crl.pki.gov.kz/nca_d_gost_2022.crl
  * https://crl.pki.gov.kz/nca_d_rsa_2022.crl
* `NCANODE_CRL_DELTA_TTL` - Время жизни Delta-CRL в кэше (по умолчанию 1440 минут)
* `NCANODE_CRL_STRICT` - Строгий режим CRL (SSRF-защита). Если `true`, on-demand загрузка CRL по адресу из проверяемого сертификата (`cRLDistributionPoints`) отключена — используются только сконфигурированные CRL (`NCANODE_CRL_URL` / `NCANODE_CA_CRL_URL`). Так сертификат злоумышленника не заставит сервер обратиться к произвольному (внутреннему) хосту. По умолчанию: `false`. Независимо от флага, адреса из сертификата, указывающие на loopback/link-local (напр. 169.254.169.254), всегда блокируются.
* `NCANODE_HTTP_CLIENT_CONNECT_TIMEOUT` - Таймаут установления TCP-соединения для исходящих HTTP-запросов в секундах (по умолчанию: 5)
* `NCANODE_HTTP_CLIENT_REQUEST_TIMEOUT` - Общий бюджет на исходящий HTTP-запрос (включая отдачу тела) в секундах. Влияет на скачивание крупных CRL (по умолчанию: 30)
* `NCANODE_HTTP_CLIENT_USER_AGENT` - HTTP заголовок User-Agent у клиента
* `NCANODE_PROXY_URL` - Прокси для HTTP-клиента. Через этот прокси будут происходить все запросы из NCANode.
* `NCANODE_PROXY_USERNAME` - Имя пользователя в прокси
* `NCANODE_PROXY_PASSWORD` - Пароль прокси
* `NCANODE_OCSP_URL` - OCSP-сервер куда будут происходить запросы. По умолчанию: http://ocsp.pki.gov.kz/
* `NCANODE_OCSP_STRICT` - Строгий режим OCSP (SSRF-защита). Если `true`, OCSP-проверка игнорирует адрес responder'а из AIA сертификата и ходит только на сконфигурированный `NCANODE_OCSP_URL`. По умолчанию: `false` (AIA-first, config-fallback).
* `NCANODE_CA_URL` - URL-ы корневых сертификатов. Они скачиваются автоматически при запуске NCANode. По умолчанию:
  * https://pki.gov.kz/cert/nca_rsa.crt
  * https://pki.gov.kz/cert/nca_gost.crt
  * https://pki.gov.kz/cert/root_gost_2022.cer
  * https://pki.gov.kz/cert/nca_gost_2022.cer
* `NCANODE_CA_TTL` - Время жизни корневых сертификатов CA (по умолчанию 1440 минут)
* `NCANODE_CA_CRL_ENABLED` - Проверка корневых сертификатов на отозванность. Если сертификат отозван, NCANode попробует его заново скачать. (По умолчанию: true)
* `NCANODE_CA_CRL_TTL` - Время жизни для CRL корневых сертификатов (по умолчанию 1440 минут)
* `NCANODE_CA_CRL_URL` - Список URL-ов откуда скачивать CRL. По умолчанию:
  * http://crl.root.gov.kz/gost.crl
  * http://crl.root.gov.kz/rsa.crl
  * http://crl.root.gov.kz/gost2015_2022.crl
  * http://crl.root.gov.kz/rsa2020.crl
* `NCANODE_TSP_URL` - URL TSP-сервера. По умолчанию: http://tsp.pki.gov.kz/
* `NCANODE_TSP_RETRIES` - Количество неудачных попыток обращения к TSP-серверу, по умолчанию: 3

## Проверка отзыва сертификатов (OCSP / CRL)

Проверка отзыва — **opt-in**: если `revocationCheck` в запросе не указан, отзыв
**не проверяется**, и отозванный (но в остальном валидный) сертификат пройдёт
как `valid: true`. В этом случае в логах пишется предупреждение (WARN). Чтобы
включить проверку, передайте `revocationCheck: ["OCSP", "CRL"]`.

Если в запросе верификации указаны обе проверки (`revocationCheck: ["OCSP", "CRL"]`),
выполняются **обе**, и отзыв, найденный любым из каналов, делает сертификат
невалидным. Особые случаи:

* **OCSP недоступен по сети** (таймаут, connection refused, ответ не парсится) —
  верификация автоматически деградирует на CRL: сертификат считается валидным,
  если свежий (не истёкший по `nextUpdate`) CRL его издателя не содержит его
  серийника. Это стандартная модель OCSP-preferred + CRL-fallback (RFC 5280 §6.3).
  В `revocations[]` такой канал помечается `"result": "UNAVAILABLE"`.
* **OCSP ответил, но ответу нельзя верить** (несовпадение nonce, битая подпись
  ответа, статус unknown) — сертификат невалиден независимо от CRL
  (`"result": "UNKNOWN"`, fail-closed).
* **CRL издателя нет в кэше** (CA не публикует CRL, или он не сконфигурирован) —
  CRL-канал помечается `"result": "UNAVAILABLE"`; это не мешает валидности при
  живом OCSP, но такой CRL не может служить fallback-источником.

CRL-проверка учитывает delta-CRL по RFC 5280 §5.2.4: если для издателя есть
и полный (base), и применимая к нему delta (`NCANODE_CRL_DELTA_URL`), они
объединяются — delta авторитетна для изменений после base (включая снятие
отзыва `removeFromCRL`). Delta обновляется чаще (меньший `nextUpdate`),
поэтому картина отзывов, а значит и свежесть CRL-fallback'а, актуальнее,
чем по одному полному CRL.

Каждый элемент `revocations[]` в ответе несёт поле `result`
(`ACTIVE` / `REVOKED` / `UNKNOWN` / `UNAVAILABLE`). Клиент, которому нужна
строгая политика «оба канала обязаны ответить», может реализовать её сам:
`valid && revocations.none { result == "UNAVAILABLE" }`.

## Запуск с переменными окружения

Например, мы хотим изменить порт и включить отладку. То мы запускаем NCANode так:

```bash
NCANODE_PORT=8080 NCANODE_DEBUG=true java -jar ./NCANode.jar
```

Для Docker необходимо использовать параметр `-e`. Например:

```bash
docker run -p 8080:8080 -v ncanode_cache:/app/cache -e NCANODE_PORT=8080 -e NCANODE_DEBUG=true -d malikzh/ncanode
```

## Запросы к NCANode

После запуска NCANode можете перейти по адресу:

[http://localhost:14579/actuator/health](http://localhost:14579/actuator/health)

В ответ придет что-то вроде:

```
{"status":"UP"}
```

### Важно знать
  
Обратите внимание, что ключи, CMS, и данные в CMS передаются в формате **Base64**. Это описано в API Reference.

И в каждом запросе не забывайте передавать заголовок `Content-Type: application/json`.