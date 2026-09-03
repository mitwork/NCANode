
![NCANode](NCANode.png)


⭐ Приложение-сервер для работы с Электронно Цифровой Подписью (ЭЦП) РК

---

![License:MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Downloads](https://img.shields.io/github/downloads/malikzh/NCANode/total.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/malikzh/ncanode)
[![Build CI and Test](https://github.com/malikzh/NCANode/actions/workflows/build-ci.yml/badge.svg)](https://github.com/malikzh/NCANode/actions/workflows/build-ci.yml)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/malikzh/NCANode)
[![codecov](https://codecov.io/gh/malikzh/NCANode/branch/master/graph/badge.svg?token=yk6ln3mlTB)](https://codecov.io/gh/malikzh/NCANode)

---

## Возможности

- Кроссплатформенный сервер (Windows, Mac OS, Linux)
- HTTP API с JSON-протоколом
- Подпись XML данных с помощью xmldsig
- Подпись WSSE для [SmartBridge](https://sb.egov.kz/)
- Подпись и верификация PDF (CAdES-T)
- Форматы AdES — CAdES, XAdES и PAdES уровней B, T, LT и LTA (совместимо с NCALayer)
- Кодирование и верификация JWT (алгоритм GG2015)
- Поддержка OCSP и CRL (при сетевой недоступности OCSP — автоматический fallback на свежий CRL)
- Проверка валидности сертификатов (включая цепочку доверия)
- Поддержка [CMS](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax)
- TSP-метки и CAdES-T для CMS / PDF
- Множественные подписи для xmldsig и CMS
- Массовые (batch) операции для всех сервисов
- Добавление подписей в уже существующие файлы CMS и XML
- ГОСТ 34.10-2015 (актуальный стандарт НУЦ РК) и новые CRL
- Тестовое покрытие на ключевые кейсы
- Docker

## Стек (ветка v4)

Эта ветка — полная переписка на Kotlin / Spring Boot 4.

- **Kotlin** 2.3.x, **Java 25** (toolchain через foojay-resolver)
- **Spring Boot** 4.0.x, **Gradle** 9.5.x
- Jakarta EE (без `javax.*` кроме JDK-native)
- KalkanCrypt 0.7.8, BouncyCastle 1.84, Apache Santuario 4.0.x, Apache PDFBox 3.0.x
- Тесты: Kotest 5.9 + MockK + Spring Boot Test

## Официальная группа в Telegram

В целях оперативного решения проблем / помощи, была создана официальная группа в Telegram:
http://t.me/ncanode

## Кому надо?

Если Вам необходимо реализовать подпись данных формата XML, PDF, JWT или произвольного на стороне сервера,
запустите NCANode и обращайтесь к нему по HTTP API.

## Кто использует?

Исходя из полученных писем от программистов, NCANode используется как в стартапах, так и в крупных страховых компаниях

## СМИ об NCANode

https://profit.kz/news/56732/Otkritij-kod-Beeline-Hacktoberfest-v-Kazahstane/

## Пример

Пример запроса (запрос информации о ключе):

```json
{
  "xml": "<?xml version=\"1.0\" encoding=\"utf-8\"?><a><b>test</b></a>",
  "signers": [
    {
      "key": "MIIHTwIBAzCCBwkGCSqGS...",
      "password": "qwerty12"
    }
  ]
}
```

Пример ответа:

```json
{
  "status": 200,
  "message": "OK",
  "xml": "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?><a><b>test</b><ds:Signature x..."
}
```

## Документация

Документацию по API можно найти на http://ncanode.kz (актуально для v3; для v4 совпадает большинство эндпоинтов).

Swagger UI поднимается локально по адресу `http://localhost:14579/swagger-ui/index.html` после запуска.

## Contributors

<a href="https://github.com/malikzh/NCANode/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=malikzh/NCANode" />
</a>

## Лицензия

Проект лицензирован под лицензией [MIT](LICENSE)

## Важно!!!

По требованию АО «НИТ» | НУЦ РК. Библиотеки `kalkancrypt-*.jar`/`knca_provider_jce_kalkan-*.jar` и `kalkancrypt-xmldsig-*.jar`
Были удалены из репозитория, поэтому для компиляции Вам необходимо подставить библиотеки
из комплекта разработчика (SDK) в директорию `/lib`.

### Сборка проекта

- JDK 25 (Gradle сам подгружает toolchain через foojay-resolver, если у вас стоит 21+)
- Gradle wrapper в комплекте (`./gradlew`) — версия 9.5

Для сборки проекта необходимо:

1. Подставить библиотеки KalkanCrypt (`knca_provider_jce_kalkan-*.jar` и `kalkancrypt-xmldsig-*.jar`) в директорию `lib/` (Их можно запросить [тут](https://pki.gov.kz/developers/))
2. `./gradlew bootJar`

Собранный jar будет лежать здесь: `build/libs/NCANode-<version>.jar` (по умолчанию `4.0.0-SNAPSHOT`).

### Запуск проекта без сборки

Проект запустить можно командой:

```bash
$ ./gradlew bootRun
```

### Запуск в Docker из готового образа

```bash
docker volume create ncanode_cache
docker run -p 14579:14579 -v ncanode_cache:/app/cache -d malikzh/ncanode
```

### Запуск через Docker Compose

Предварительно нужно собрать проект через gradle и сгенерировать jar файлы

```bash
docker compose build  // сборка образа
docker compose up -d  // запуск контейнера
docker compose ps  // проверка статуса контейнера
docker compose stop  // остановка контейнера
```

### После запуска

Проверить можно, перейдя на страницу: http://localhost:14579/actuator/health

## Как отправить Pull Request

Если вы нашли и исправили ошибку, пожалуйста, отправьте Pull Request — я обязательно его рассмотрю.  
Если требуется срочное рассмотрение вашего PR, напишите в группу [Telegram](http://t.me/ncanode).

Сделано с ❤️
