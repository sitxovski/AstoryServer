# NpcServer — пересборка сетки секторов после `CSectorManager::SetMapInfo` (code-cave)

- **Дата:** 2026-08-03
- **Статус:** ✅ ПРИМЕНЁН (ожидает рестарта стойки)
- **Процесс / файлы:**
  - `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\NpcServer\NpcServer.exe`
  - `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\Indun_NpcServer\NpcServer.exe`
- **Тип:** бинарный патч (code-cave в `.text` + подмена одного `call`)
- **Отчёт-основание:** `Reports/npcserver_serialization_profile.md` (спам `OnUserSearch() incorrect Sector->m_Index`)

---

## 1. Дефект (что реверснуто)

### 1.1 Сетка строится по КОНСТАНТАМ до чтения ini

`CSectorManager::Init` = `sub_41B1A0` @`0x41B1A0` (`NpcServer.exe.c:18841`) —
вызывается один раз на каждый CAi-поток (`NpcServer.exe.c:55811`) и **прошивает
геометрию жёстко**:

```
0041B1D6  mov eax, 0x200        ; a1[3] = MapW  = 512
0041B1DB  mov [ebp+0xC], eax    ; a1[4] = MapH  = 512
0041B1E1  mov eax, 0x1E         ; a1[5] = SecW  = 30
          ...                   ; a1[6] = SecH  = 30
0041B1EC  mov eax, 0x12         ; a1[7] = CountX = 18
          ...                   ; a1[8] = CountZ = 18
0041B1F9  mov eax, 0x144        ; a1[9] = Count  = 324
```

Затем создаются 324 объекта `CSector` (по `0x7F0` байт), каждому проставляется
`m_Index = z*18 + x`, `m_X`, `m_Z`, прямоугольник сектора и расширенный
прямоугольник, и **линкуются 9 соседей** штатной `CSector::SetAroundSector` =
`sub_41BEE0` @`0x41BEE0`.

### 1.2 Формула соседей — КОРРЕКТНА (важно!)

`sub_41BEE0(this@eax, CountX@ecx, ppSector@edi, CountZ@stack)`; порядок слотов
`m_pAround[0..8]` = N, NE, E, SE, S, SW, W, NW, self. Проверка границ есть у
каждого направления и wrap-around **отсутствует**:

| слот | условие | значение |
|---|---|---|
| 0 (N) | `z-1 >= 0` | `pp[idx-CountX]` |
| 1 (NE) | `x+1 < CountX && z-1 >= 0` | `pp[idx-CountX+1]` |
| 2 (E) | `x+1 < CountX` | `pp[idx+1]` |
| 3 (SE) | `x+1 < CountX && z+1 < CountZ` | `pp[idx+CountX+1]` |
| 4 (S) | `z+1 < CountZ` | `pp[idx+CountX]` |
| 5 (SW) | `x-1 >= 0 && z+1 < CountZ` | `pp[idx+CountX-1]` |
| 6 (W) | `x-1 >= 0` | `pp[idx-1]` |
| 7 (NW) | `x-1 >= 0 && z-1 >= 0` | `pp[idx-CountX-1]` |
| 8 | — | `this` |

Несуществующий сосед = `NULL`, а `OnUserSearch` `NULL` пропускает. Дубликатов
нет: каждое направление — отдельная ячейка. (Идентичный код в GameServer:
`sub_46DC70` @`0x46DC70` — там он вызывается ПОСЛЕ чтения конфига, поэтому
GameServer здоров.)

### 1.3 Настоящая причина: `SetMapInfo` меняет ЧИСЛА, не перестраивая сетку

`CSectorManager::SetMapInfo` = `sub_41A6C0` @`0x41A6C0` (`NpcServer.exe.c:18295`),
вызывается из `CAi::Initialize` = `sub_458290` @`0x4582AD`, перезаписывает
скалярные поля значениями из `ini\SectorInfo.ini` (через `MapInfo`-структуру
`dword_4DBF40`, поля `+36..+48`, посчитанные в `NpcServer.exe.c:56249-56276`):

```
[mgr+0x04]=[mgr+0x0C]=Map_Width   [mgr+0x08]=[mgr+0x10]=Map_Height
[mgr+0x14]=Sector_Width           [mgr+0x18]=Sector_Height
[mgr+0x1C]=ceil(W/SW)=CountX      [mgr+0x20]=ceil(H/SH)=CountZ
[mgr+0x24]=CountX*CountZ=Count    ← m_SectorCount
```

**и НИ ОДИН `CSector` при этом не пересобирается.** Объекты остаются с
`m_Index`/`m_X`/`m_Z`/rect/соседями от сетки 18×18 по 30 тайлов.

Совпадение работало только при `Sector_Width = 30` (оригинал): `ceil(512/30)=18`,
`18*18=324` — числа сходились с прошитыми.

### 1.4 Как это проявляется

| `Sector_*` | сетка по ini | `m_SectorCount` | реально в `CSector` | эффект |
|---|---|---|---|---|
| 30 | 18×18 = 324 | 324 | 18×18 = 324 | всё сходится (оригинал) |
| 256 | 2×2 = 4 | 4 | индексы 0..323, шаг соседа 18 | соседи сектора 0 = 1, 18, 19 → лог `incorrect Sector->m_Index 18/19/20` |
| 64 | 8×8 = 64 | 64 | шаг соседа 18/17/19 | лог `incorrect ... 64…81` |

Лог из `CSectorManager_20260803.txt` подтверждает точь-в-точь: в 00:00 (сектор 256)
печатались **18, 19, 20**; после 16:16 (сектор 64) — **64…81** с максимумом на
68/69/70 (= `63+…`). Это и есть 2688 строк/с → 663 МБ/сут через
однофайловый логгер `sub_408DC0` (open+write+close на строку).

Ломался не только лог:

1. **Соседи геометрически неверные.** При секторе 64 «южный сосед» = `idx+18`,
   а должен быть `idx+8`. Мобы искали игроков в чужих секторах → часть игроков
   не видна, часть «видна» с другого конца карты.
2. **Прямоугольники секторов от сетки 30.** `CheckMonsterInSector`/`CheckPlayerInSector`
   (`NpcServer.exe.c:19090, 19319, 19367`) сверяют координаты с `CSector` rect
   `[+0x7D0..+0x7DC]`. При секторе 64 моб с `x=50` попадает в сектор 0, чей rect
   `(0,0,29,29)` → «вне сектора» КАЖДЫЙ кадр → постоянное переселение
   Delete/AddMonster с захватом критических секций (лишний CPU и churn списков).
3. **Расхождение `m_SectorIndex` моба.** `SetMonsterToSector` (`sub_41B830`) пишет
   в `+30404` индекс, посчитанный по ini, а `CSector::AddMonster` пишет в `+30400`
   **`sector->m_Index` от старой сетки** (до 323). Именно `+30400` уходит в пакеты
   к GameServer → у GameServer `ppSector[]` всего `Count` элементов и **нет верхней
   проверки** (`Send_SectorInAddMonsterInfo` @`0x41DE10`: только `if (a2 >= 0)`),
   т.е. чтение за границей массива. После этого патча оба поля совпадают и
   источник OOB исчезает.

---

## 2. Фикс

Хук на единственный вызов `SetMapInfo` в `CAi::Initialize`; после успешного
`SetMapInfo` cave пересобирает сетку **под фактические значения из ini** —
работает при ЛЮБОМ размере сектора (30/64/256/…), пока `CountX*CountZ <= 324`
(столько `CSector` физически выделено конструктором).

### 2.1 Точка хука

```
файл-офсет 0x0582AD (VA 0x4582AD), 5 байт
БЫЛО:  E8 0E 24 FC FF    call 0x41A6C0     ; CSectorManager::SetMapInfo
СТАЛО: E8 AE C6 00 00    call 0x464960     ; cave
```

### 2.2 Code-cave

Хвостовое нулевое заполнение секции `.text` (`VirtualSize 0x6395A`,
`SizeOfRawData 0x64000` → зона `0x46495A..0x465000` замаплена и исполняема,
1702 нулевых байта). Занято 314 байт по **VA `0x464960` = файл-офсет `0x64960`**;
заголовки PE НЕ трогались.

```asm
; --- вход хука: [esp]=ret, [esp+4]=mapIndex, esi=pCSectorManager ---
00464960  push  esi
00464961  push  dword [esp+8]        ; переложить аргумент
00464965  call  0x41A6C0             ; оригинальный SetMapInfo (ret 4)
0046496A  pop   esi
0046496B  test  al, al
0046496D  jnz   0x464974             ; ошибка SetMapInfo -> не трогаем сетку
0046496F  call  0x464977             ; rebuild
00464974  ret   4

; --- rebuild(esi = mgr), все регистры сохраняются ---
00464977  pushad
          edi = [esi+0x00]                       ; m_ppSector
          guard: edi != 0, CountX>0, CountZ>0,
                 CountX*CountZ == m_SectorCount,
                 m_SectorCount <= 324,           ; ёмкость массива CSector
                 SecW>0, SecH>0                  ; иначе выход без изменений
          проход 1 (i = 0..Count-1):  z = i / CountX ; x = i % CountX
                 [sec+0x24]=i  [sec+0x28]=x  [sec+0x2C]=z
                 [sec+0x7D0]=x*SecW                       ; left
                 [sec+0x7D8]=min(left+SecW-1, MapW-1)     ; right
                 [sec+0x7D4]=z*SecH                       ; top
                 [sec+0x7DC]=min(top+SecH-1, MapH-1)      ; bottom
                 [sec+0x7E0]=max(left-SecW, 0)            ; расширенный rect
                 [sec+0x7E4]=max(top-SecH, 0)
                 [sec+0x7E8]=min(right+SecW, MapW-1)
                 [sec+0x7EC]=min(bottom+SecH, MapH-1)
          проход 2 (i = 0..Count-1):
                 call 0x41BEE0                   ; штатный SetAroundSector
                                                 ; eax=pp[i], ecx=CountX, edi=pp, push CountZ
00464A98  popad
00464A99  ret
```

Формулы прямоугольников скопированы 1:1 с конструктора `sub_41B1A0`
(`NpcServer.exe.c:18936-18973`), включая обрезку по краю карты и «сдвиг на
сектор» для расширенного прямоугольника.

**Почему не вызывается штатный `CSector::SetInfo` (`sub_41C180`):** он попутно
переинициализирует три `CDirectLinkArray` через `sub_450890`, а тот делает
`operator new` — повторный вызов дал бы утечку ~7 КБ на сектор. Ёмкости списков
(мобы 200 / игроки 200 / NPC 50) от размера сетки не зависят и уже
проинициализированы конструктором, поэтому cave пишет только геометрию.

Секторы с `i >= m_SectorCount` остаются со старыми данными — они недостижимы
(все обходы ограничены `m_SectorCount`).

### 2.3 Ограничение

`m_SectorCount <= 324`, т.к. конструктор выделяет ровно 324 `CSector`.
Покрывает `Sector_Width >= 29` (512/29 → 18×18). Для сектора **меньше 30**
(например 16 → 32×32 = 1024) cave тихо не сработает и поведение останется
сегодняшним (сломанным) — понадобится расширенная версия с доаллокацией.

### 2.4 Проверка ПЕРЕД рестартом

- Патч применён к обеим копиям; байты в точке хука сверены с оригиналом перед
  записью, cave-зона проверена на нулевое заполнение.
- **Эмуляция реального пропатченного кода (Unicorn x86)**: `rebuild` запущен на
  синтетическом менеджере для `Sector = 30 / 64 / 256`, включая **настоящий**
  `sub_41BEE0` из бинаря. Для всех трёх размеров совпали 1:1 с эталонной моделью:
  `m_Index`, `m_X`, `m_Z`, оба прямоугольника и все 9 ссылок соседей.
  Скрипты лежат рядом с этим доком:
  `AstoryServer/Docs/NpcServer/emu_test_sectorgrid.py` (проверка) и
  `AstoryServer/Docs/NpcServer/patch_npc_sectorgrid.py` (сам патчер; требует
  `keystone-engine`, `capstone`, `pefile`, для проверки — `unicorn`).
  Пример при секторе 256 (2×2): sect0 → соседи `E=1, SE=3, S=2, self=0`, остальные
  `NULL`; rect `(0,0,255,255)`; расширенный `(0,0,511,511)`.

### 2.5 MD5

| Файл | было (до этого патча) | стало |
|---|---|---|
| `NpcServer\NpcServer.exe` | `465D7EC05CD96D98FCD174AE19D64CFD` | **`D292E4EC4EDFD5040D8FB39382664EAB`** |
| `Indun_NpcServer\NpcServer.exe` | `4EBE81875921176AD26CECE802458669` | **`C1B28FC077F180F720B9EAE8830C624A`** |

Размер не менялся: 516 096.

---

## 3. Бэкапы

| Что | Куда |
|---|---|
| `NpcServer\NpcServer.exe` | `NpcServer\NpcServer.exe.prefix_neighbors_20260803` |
| `Indun_NpcServer\NpcServer.exe` | `Indun_NpcServer\NpcServer.exe.prefix_neighbors_20260803` |

(В обоих бэкапах уже присутствует предыдущий патч импорта `OutputDebugStringA`→
`SetLastError`; полностью «заводской» бинарь — `*.preboost_20260803`.)

## 4. Откат

Одной командой (стойка должна быть остановлена):

```
\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\_dbg\rollback_gridfix_20260803.bat
```

Скрипт возвращает оба `NpcServer.exe` из `*.prefix_neighbors_20260803` **и**
переводит 5 конфигов обратно на сектор 64 (из `*.pre256fix_20260803`).

Только вернуть сектор 64, оставив фикс сетки:
`\\@@ASTORY_SERVER_HOSTNAME@@\…\v2\_dbg\sector64_keep_gridfix_20260803.bat`.

## 5. Рестарт

**Требуется полный рестарт стойки** (правится код, читаемый при инициализации
AI-потоков). Перезапускает пользователь.

## 6. Риски / связанное

- Cave лежит в «хвосте» `.text` за `VirtualSize`, но внутри `SizeOfRawData` —
  область гарантированно замаплена загрузчиком. Заголовки не изменены,
  CheckSum не пересчитывался (как и в предыдущем патче).
- Связано: `_Common/aoi-sector-size-256-after-gridfix.md` (возврат сектора 256),
  `GameServer/sector-index-bounds-guard-OPEN.md` (не применённая защита от OOB).
- После рестарта ожидается: файл `NpcServer\Error_Log\CSectorManager_YYYYMMDD.txt`
  **перестаёт расти** (был 663 МБ/сут), исчезает переселение мобов между
  секторами каждый кадр.
