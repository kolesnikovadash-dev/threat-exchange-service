# Information Exchange Service

REST-сервис на Go для хранения и обмена сведениями об известных угрозах по MD5. Сервис не анализирует файлы и не определяет их вредоносность.

## Запуск из ZIP-архива

Проект можно передавать обычным ZIP-архивом — доступ к GitHub для сборки **не требуется**, даже если исходный репозиторий приватный.

1. Распакуйте архив и откройте терминал в папке `threat-exchange-service`, содержащей `docker-compose.yml`
2. Убедитесь, что установлен и запущен Docker с поддержкой Compose
3. Выполните:

```bash
docker compose up --build -d
```

При первом запуске Docker загрузит необходимые образы, а сборка Go загрузит внешние зависимости. Для этого нужен доступ к интернету, **но не к приватному GitHub-репозиторию**. Go-модуль `github.com/kolesnikovadash-dev/threat-exchange-service` и его внутренние пакеты уже включены в архив.

Сервис доступен по адресу `http://localhost:8080`. Проверьте запуск:

```bash
curl -i http://localhost:8080/health
```

Для просмотра журналов:

```bash
docker compose logs -f api
```

Чтобы остановить контейнеры без удаления данных:

```bash
docker compose down
```

Если порт `8080` занят, измените **внешний** порт в `docker-compose.yml` (например, `127.0.0.1:8081:8080`), после чего используйте `http://localhost:8081`.

Для сборки через Docker Go на компьютере устанавливать не требуется. Для локальной сборки без Docker нужен Go 1.26+.

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

Для интеграционных тестов нужна **отдельная** база PostgreSQL, доступная из терминала и имеющая имя, заканчивающееся на `_test`. База `db` из Compose не опубликована на хосте, поэтому адрес `localhost:5432` в примере ниже применим только к PostgreSQL, запущенной отдельно:

```bash
make test-integration TEST_DATABASE_URL='postgres://user:pass@localhost:5432/threats_test?sslmode=disable'
```

При первом создании тома PostgreSQL автоматически выполняется `db/migrations/000001_init.up.sql`, которая создаёт таблицы `threat` и `file_hash`. При последующих запусках контейнера SQL из `/docker-entrypoint-initdb.d/` повторно не выполняется.

## Документация

- [Архитектура и границы слоёв](docs/architecture.md)
- [ER-диаграмма БД](db/normalized/er_diagram.md)
- [Таблицы и ограничения](db/normalized/relations.md)
- [Контракт OpenAPI](api/openapi.yaml)

Сервис предназначен для локального запуска: авторизация и TLS в API не реализованы. Для публикации потребуется дополнительная защита.
