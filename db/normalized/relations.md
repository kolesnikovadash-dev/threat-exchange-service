# Реляционная модель

## `threat` — справочник угроз

| Поле | Ограничения | Смысл |
| --- | --- | --- |
| `id` | `PRIMARY KEY` | внутренний идентификатор |
| `name` | `UNIQUE NOT NULL`, до 255 символов | название угрозы |
| `description` | `NOT NULL`, по умолчанию `''` | общее описание |
| `severity` | `CHECK`, по умолчанию `unknown` | общая степень опасности |
| `threat_type` | `CHECK`, по умолчанию `other` | тип угрозы |
| `updated_at` | `NOT NULL` | время изменения общих данных |

Значения `severity`: `unknown`, `low`, `medium`, `high`, `critical`.
Значения `threat_type`: `other`, `trojan`, `worm`, `ransomware`, `spyware`.

## `file_hash` — файлы

| Поле | Ограничения | Смысл |
| --- | --- | --- |
| `md5` | `PRIMARY KEY`, 32 строчных hex-символа | хеш файла |
| `threat_id` | `NOT NULL`, `FOREIGN KEY threat(id)` | ссылка на угрозу |
| `created_at` | `NOT NULL` | дата регистрации MD5 |
| `updated_at` | `NOT NULL` | дата изменения привязки MD5 |

Связь `threat` → `file_hash`: **1:N**. Индекс `file_hash_threat_id_idx` ускоряет работу по внешнему ключу. `ON DELETE RESTRICT` не допускает удаления угрозы с привязанными файлами.

## Правила сервиса

- `GET /info/{md5}` объединяет таблицы через JOIN и не показывает внутренний `threat_id`
- `POST /info` создаёт запись для MD5 и, если нужно, новую запись угрозы; общие метаданные существующей угрозы не перезаписываются
- `PUT /info/{md5}` меняет привязку конкретного MD5; обновление `description`, `severity`, `threat_type` затрагивает все MD5 этой угрозы
- в HTTP-ответе `created_at` — дата создания записи MD5, `updated_at` — наиболее поздняя дата изменения записи MD5 или общих сведений об угрозе

Схема создаётся миграцией [`000001_init.up.sql`](../migrations/000001_init.up.sql). Обратная миграция — [`000001_init.down.sql`](../migrations/000001_init.down.sql).
