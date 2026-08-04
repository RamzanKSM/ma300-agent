# MA300 agent

Локальный bridge между С2000-BIOAccess-MA300 и фронтендом ресепшена.

```text
MA300 --pyzk/UDP--> ma300-agent --SSE--> фронтенд --HTTP--> основной backend
```

Agent получает от MA300 объект `Attendance`, публикует его в SSE и **никогда не
создаёт посещение сам**. Фронтенд использует `userId` как идентификатор карты,
вызывает обычный `POST /api/v1/admin/reception/check-ins/card`, а основной
backend находит спортсмена через `card_bindings` и применяет все правила допуска.

## Требования

- Python 3.11 или новее;
- сетевой доступ с компьютера ресепшена к MA300 на UDP-порт `4370`;
- зарегистрированные в MA300 `user_id` привязаны в основной системе как карты.

## Установка и запуск

```bash
git clone <repository-url> ma300-agent
cd ma300-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
set -a; source .env; set +a
python app.py
```

При успешном подключении агент пишет в stdout:

```text
Connected to MA300 at 192.168.1.201:4370
Waiting for MA300 live events
EVENT: <Attendance>: 2265 : 2026-06-25T22:46:45 (2, 0)
```

Если `live_capture()` возвращает `None`, это нормальный timeout: агент пишет
`time out` и продолжает ждать новое событие. При сетевой ошибке он отключается и
переподключается через `MA300_RECONNECT_DELAY_SECONDS` секунд.

## HTTP contract

Agent по умолчанию слушает только `127.0.0.1:8765`.

```text
GET /healthz
GET /events
```

`GET /events` — Server-Sent Events. При идентификации он отдаёт:

```text
event: attendance
data: {"type":"attendance","eventId":"...","userId":"2265","timestamp":"2026-06-25T22:46:45","status":2,"punch":0}
```

`eventId` уникален для события и нужен фронтенду для защиты от повторной
обработки. `status`, `punch` и `timestamp` сохраняются в контракте для
диагностики; решение о посещении принимает основной backend по `userId`.

## Подключение фронтенда

В `.env.local` фронтенда ресепшена:

```text
VITE_RECEPTION_WORKSTATION_MODE=CARD_READER
VITE_RECEPTION_DEVICE_EVENTS_URL=http://127.0.0.1:8765/events
```

`VITE_RECEPTION_MOCK_CONTROL_URL` для реального агента не задаётся: у него нет
endpoint'ов для имитации считываний.

## Настройки

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `MA300_HOST` | — | IP-адрес считывателя, обязательна. |
| `MA300_PORT` | `4370` | Порт MA300. |
| `MA300_TIMEOUT_SECONDS` | `10` | Timeout `pyzk`. |
| `MA300_PASSWORD` | `0` | Пароль устройства. |
| `MA300_FORCE_UDP` | `true` | Передать `force_udp` в `pyzk`. |
| `MA300_OMIT_PING` | `true` | Передать `ommit_ping` в `pyzk`. |
| `MA300_RECONNECT_DELAY_SECONDS` | `3` | Пауза перед переподключением. |
| `AGENT_HOST` | `127.0.0.1` | Адрес SSE-сервера. Не меняйте без сетевой защиты. |
| `AGENT_PORT` | `8765` | Порт SSE-сервера. |

## Проверка без фронтенда

После старта проверьте здоровье процесса:

```bash
curl http://127.0.0.1:8765/healthz
```

И откройте поток событий в отдельном терминале:

```bash
curl -N http://127.0.0.1:8765/events
```

Затем приложите карту или палец к MA300. В терминале появится событие `attendance`.
