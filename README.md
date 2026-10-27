# Information Exchange Service

REST-сервис на Go для хранения и обмена сведениями об известных угрозах по MD5. Сервис не анализирует файлы и не определяет их вредоносность.

## Запуск

Нужен Docker с поддержкой Compose.

```bash
make docker-up
```

API доступен по адресу `http://localhost:8080`. Остановить контейнеры без удаления данных:

```bash
make docker-down
```

Если порт `8080` занят, его можно изменить в `docker-compose.yml` (слева от двоеточия в `ports`).

## REST API

| Метод | Маршрут | Назначение |
| --- | --- | --- |
| POST | `/info` | создать новую запись |
| GET | `/info/{md5}` | получить сведения об угрозе |
| PUT | `/info/{md5}` | обновить существующую запись |
| GET | `/health` | проверить доступность HTTP-сервера |

Пример создания записи:

```bash
curl -i -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{"md5":"a1b2c3d4e5f678901234567890abcdef","name":"Trojan.Win32.Generic","severity":"high"}'
```

MD5 в примере используется только для демонстрации формата, это не сведения о реальной угрозе.

Полный контракт запросов и ответов — [`api/openapi.yaml`](api/openapi.yaml).

## Разработка

```bash
make build
make test
make lint
make fmt
make coverage
```

Для запуска без Docker нужны Go 1.26+ и PostgreSQL. Пример переменных окружения — `.env.example`. Переменные `PORT` и `DATABASE_URL` задаются в окружении; `.env` автоматически не загружается.

Для интеграционных тестов нужна **отдельная** PostgreSQL с именем БД, заканчивающимся на `_test`:

```bash
make test-integration TEST_DATABASE_URL='postgres://user:pass@localhost:5432/threats_test?sslmode=disable'
```

При первом запуске контейнера БД схема создаётся из `db/migrations/000001_init.up.sql`. Для уже существующего тома этот SQL автоматически не выполняется повторно.

## Документация

- [Архитектура и границы слоёв](docs/architecture.md)
- [Нормализованная схема БД и правила обновления](db/normalized/README.md)
- [Контракт OpenAPI](api/openapi.yaml)

Сервис предназначен для локального запуска: авторизация и TLS в API не реализованы. Для публикации потребуется дополнительная защита.
