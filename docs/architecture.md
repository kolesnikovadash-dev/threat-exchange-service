# Архитектура

Сервис хранит информацию об известных угрозах по MD5. Анализ и сканирование файлов в его задачи не входят.

## Поток запроса

```text
HTTP request
    ↓
server
    ↓
delivery/threat
    ↓
usecase/threat
    ↓
repository/threat
    ↓
PostgreSQL
```

## Структура

| Пакет | Назначение |
| --- | --- |
| `cmd/server` | точка входа, подключение к БД, запуск и остановка HTTP-сервера |
| `internal/app` | создание конфигов и сборка зависимостей (`CreateConfig`) |
| `internal/server` | маршрутизация HTTP |
| `internal/delivery` | конфигурация HTTP-обработчиков |
| `internal/delivery/threat` | JSON-запросы, статусы, обработка ошибок |
| `internal/dto/threat/request.go` | DTO для входных JSON-запросов |
| `internal/usecase` | конфигурация бизнес-логики |
| `internal/usecase/threat/threat.go` | сценарии создания, поиска и обновления |
| `internal/usecase/threat/validation.go` | проверка и нормализация входных данных |
| `internal/repository` | конфигурация слоя хранения и создание пула PostgreSQL |
| `internal/repository/threat/postgres.go` | SQL-запросы и транзакции |
| `internal/models` | основные модели угрозы |
| `internal/apperrors` | общие ошибки приложения |
| `internal/httputil` | формирование JSON-ответов |
| `internal/config` | чтение параметров окружения |

В `internal/app/config.go` создаются `Repositories`, `Usecases` и `Handlers`. Каждый корневой пакет слоя (`repository`, `usecase`, `delivery`) имеет собственный `config.go`. Конфигурации принимают интерфейсы и не зависят от конкретных реализаций соседних слоёв, что позволяет заменять зависимости в тестах.

## Интерфейсы и зависимости

`delivery/threat` знает только интерфейс `ThreatUsecase`, а `usecase/threat` — только `ThreatRepository`. Конкретные реализации создаются при сборке приложения, поэтому бизнес-логика не зависит от HTTP и pgx.

`server.Config` получает HTTP-обработчики и не импортирует `delivery`. Общие пакеты `models`, `apperrors` и `httputil` используются по назначению.

## Формат HTTP-ответов

`httputil.WriteJSON`, `WriteOK` и `WriteError` формируют JSON-ответы. Формат ответа соответствует OpenAPI: успешные данные не оборачиваются в `data`, а ошибки — в `error`:

- успешный ответ: `{ "md5": "...", "name": "...", ... }`
- ответ об ошибке: `{ "message": "...", "details": "..." }`

## Валидация

- delivery: проверка `Content-Type`, корректности одного JSON-объекта, неизвестных полей, `null`, лимита 64 KiB
- usecase: MD5 длиной 32 hex-символа, имя 1–255 символов, описание не более 2048 символов, разрешённые перечисления
- БД: ключи, уникальность, CHECK, внешние ключи

## Обновление угрозы

Одна запись `threat` связана с несколькими MD5. При PUT с тем же `name` изменение `severity`, `description` и `threat_type` изменяет общие сведения для всех соответствующих MD5. Если имя меняется, конкретный MD5 привязывается к другому названию.

Описание БД: [`../db/normalized/er_diagram.md`](../db/normalized/er_diagram.md) и [`../db/normalized/relations.md`](../db/normalized/relations.md). API: [`../api/openapi.yaml`](../api/openapi.yaml).
