# Indun_NpcServer — импорт `OutputDebugStringA` → `SetLastError`

- **Дата:** 2026-08-03
- **Статус:** ✅ ПРИМЕНЁН (ожидает рестарта стойки)
- **Процесс / файл:** `Indun_NpcServer` — `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\Indun_NpcServer\NpcServer.exe`
- **Тип:** бинарный патч (таблица имён импорта)
- **Отчёт-основание:** `Reports/npcserver_ai_patch_options.md` → «Дешёвые варианты» → (В) В1

## ЧТО изменено

Файл **побайтово идентичен** `NpcServer\NpcServer.exe` (обе копии до правки — MD5 `47BF1839632BBA0B109F26AFEE0C2434`), поэтому **смещение и байты те же**:

```
0x0007AA9C:  8D 02 "OutputDebugStringA" 00 00     →     00 00 "SetLastError" 00 + 7×00
```

Полное обоснование, проверка всех 19 call-сайтов, подтверждение экспорта `SetLastError` в 32-битном `kernel32.dll` сервера и результат живого запуска — в
**`../NpcServer/import-outputdebugstring-to-setlasterror.md`** (не дублируем).

Здесь же, в этом файле, применена **вторая** правка — переименование waitable-таймеров (см. `waitable-timer-name-collision.md`).

## Хеши этого файла

| Состояние | MD5 |
|---|---|
| оригинал | `47BF1839632BBA0B109F26AFEE0C2434` |
| после В1 + переименования таймеров | **`4EBE81875921176AD26CECE802458669`** |

> Внимание: MD5 копий NpcServer теперь **РАЗНЫЕ** (`465D7E…` у main, `4EBE81…` у Indun) — так и задумано, раньше они совпадали.

## Бэкап

`\\@@ASTORY_SERVER_HOSTNAME@@\...\v2\Indun_NpcServer\NpcServer.exe.preboost_20260803` (оригинал, MD5 `47BF1839…`).

## Как ОТКАТИТЬ

`copy /Y "@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\Indun_NpcServer\NpcServer.exe.preboost_20260803" "@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\Indun_NpcServer\NpcServer.exe"` → рестарт стойки.
Откат вернёт **обе** правки сразу (импорт + имена таймеров).

## Рестарт

Обязателен рестарт всей стойки.
