# Настройки ОС сервера: план электропитания, парковка ядер, приоритеты, исключения Defender (вариант А)

- **Дата:** 2026-08-03
- **Статус:** ✅ ДЕЙСТВУЕТ (питание и Defender — сразу; приоритеты — со следующего `start.bat`)
- **Машина:** `@@ASTORY_SERVER_HOSTNAME@@` (@@ASTORY_SERVER_LAN_IP@@) — Windows Server 2019 Standard, Intel Xeon E5-2623 v3 @3.00 ГГц, **1 сокет / 4 ядра / 8 логических**, папка стойки `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2` (= `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2`)
- **Тип:** настройки ОС + правка `start.bat`
- **Отчёт-основание:** `Reports/npcserver_ai_patch_options.md` → «Дешёвые варианты» → (А) А1/А2/А3

## А1 — план электропитания и парковка ядер

**Симптом:** при загрузке CPU 2 % фактическая частота держалась **2.40 ГГц** при базовых 3.00 ГГц. Замер до правки: активная схема = `381b4222-f694-41f0-9685-ff5bb260df2e` (**Сбалансированная**). При этом `PROCTHROTTLEMIN`/`MAX` в ней уже были 100 % → просадку давала именно **парковка ядер** (`CPMINCORES` < 100). 21 AI-поток, просыпающийся каждые 30 мс — классический анти-паттерн для Core Parking.

| Ключ | Было | Стало |
|---|---|---|
| Активная схема | `381b4222-…` Balanced | **`8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c` High performance** |
| `SUB_PROCESSOR / CPMINCORES` (мин. ядер вне парковки), AC и DC | по умолчанию (скрыт) | **100 %** (парковка выключена) |
| `SUB_PROCESSOR / PROCTHROTTLEMIN`, AC и DC | 100 % | 100 % (подтверждено) |
| `SUB_PROCESSOR / PROCTHROTTLEMAX`, AC | 100 % | 100 % (подтверждено) |

**Результат сразу после применения:** `Win32_Processor.CurrentClockSpeed` = **2997 МГц** (было ~2400).

Применённые команды (выполнялись на сервере от SYSTEM):
```powershell
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -attributes SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE      # снять скрытие настройки
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES     100
powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES     100
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT
```

> «Ultimate Performance» (`e9a42b02-d5df-448d-aa00-03f14749eb61`) на машине присутствует, но **не** включалась: для серверной нагрузки поверх High performance она даёт околонулевой прирост, зато полностью снимает idle-состояния.

**Откат А1:** `powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e` (вернуть Сбалансированную). Скрытие настройки парковки обратно: `powercfg -attributes SUB_PROCESSOR CPMINCORES +ATTRIB_HIDE`.
**Рестарт не нужен** — применяется мгновенно.

## А2 — приоритет процессов High (через `start.bat`)

Задан **персистентно**, правкой запускающего скрипта — а не разовым `Set-Process`, который слетает при каждом рестарте.

Файл `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\start.bat`, строки 57-71 — во все 4 запуска добавлены заголовок окна и ключ `/high` (= `HIGH_PRIORITY_CLASS`):

```bat
БЫЛО                            СТАЛО
start NpcServer.exe 21     →    start "NpcServer"        /high NpcServer.exe 21
start NpcServer.exe 21     →    start "Indun_NpcServer"  /high NpcServer.exe 21
start GameServer.exe       →    start "GameServer"       /high GameServer.exe
start GameServer.exe       →    start "Indun_GameServer" /high GameServer.exe
```

- **Realtime намеренно НЕ ставился**: на 4 физических ядрах `REALTIME_PRIORITY_CLASS` вытесняет системные потоки ввода-вывода и сети — риск подвесить машину.
- **Affinity вручную НЕ прибивалась**: 4 ядра, планировщик Windows распределит 21 преимущественно спящий поток лучше любой ручной маски; жёсткая маска только сузила бы выбор.
- Прочие процессы (DBManager, ChannelManager, LoginManager, node-сервера) оставлены Normal — они не в горячем пути кадра AI.

**Бэкап:** `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\start.bat.preboost_20260803` (MD5 оригинала `0D2EB9DB998E05CF820C1329A0D5C2F4`).
**Откат А2:** вернуть бэкап поверх `start.bat`. **Вступает в силу со следующего запуска стойки.**

## А3 — исключения Microsoft Defender

На сервере активен **только** Defender (`WinDefend` Start=2, `WdNisSvc` Start=3; сторонних AV и политик `Policies\Microsoft\Windows Defender` нет). Realtime-защита была включена, исключений не было ни одного.

**Зачем:** логгер `sub_408DC0` делает `_open` + `write` + `close` на КАЖДУЮ строку (~20/с). Объём за сутки: `CSectorManager_20260803.txt` **600 МБ**, `ProcessTime_20260803.txt` **130 МБ** (за 02.08 — 949 МБ и 230 МБ). Каждый `close` — событие для realtime-сканера.

Добавлено:

| Тип | Значение |
|---|---|
| `ExclusionPath` | `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2` |
| `ExclusionProcess` | `NpcServer.exe`, `GameServer.exe`, `ChannelManager.exe`, `DBManager.exe`, `LoginManager.exe` |

```powershell
Add-MpPreference -ExclusionPath '@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2'
Add-MpPreference -ExclusionProcess NpcServer.exe,GameServer.exe,ChannelManager.exe,DBManager.exe,LoginManager.exe
```

**Откат А3:**
```powershell
Remove-MpPreference -ExclusionPath '@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2'
Remove-MpPreference -ExclusionProcess NpcServer.exe,GameServer.exe,ChannelManager.exe,DBManager.exe,LoginManager.exe
```
**Рестарт не нужен.**

## Как это применялось (канал доступа)

Рабочая станция и сервер — **разные машины**. WinRM и DCOM на `@@ASTORY_SERVER_HOSTNAME@@` закрыты (`Отказано в доступе`), но доступны SMB-шары (в т.ч. `admin$`/`c$`) и удалённый планировщик задач. Настройки ОС применены разовой задачей `ASDA_OsBoost` (запуск от SYSTEM, `/rl HIGHEST`), **задача после выполнения удалена**. Скрипт и его протокол с замерами «до/после» остались на сервере:

- `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_dbg\boost_os_20260803.ps1`
- `@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_dbg\boost_os_20260803.log`

## Риски

- А1/А3 — **нулевой риск**, откат мгновенный, без рестарта.
- А2 — низкий: High-приоритет 4 игровых процессов на 4-ядерной машине. Если появятся признаки голодания сети/диска (лаги DBManager, отвалы клиентов) — убрать `/high` из `start.bat` (или вернуть бэкап) и перезапустить стойку.
