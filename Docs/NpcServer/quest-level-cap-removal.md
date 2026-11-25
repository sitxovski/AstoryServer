# NpcServer — снятие ВЕРХНЕЙ границы уровня у приёма заданий (данные)

| Поле | Значение |
|---|---|
| **Дата** | 2026-08-23 |
| **Статус** | 🟡 **подготовлено, НЕ применено** — шара только на чтение, подменяет владелец |
| **Процесс** | `NpcServer` **и** `Indun_NpcServer` |
| **Файл** | `\\@@ASTORY_SERVER_HOSTNAME@@\H(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\NpcServer\Quest\ConditionTable.Bin`<br>`\\@@ASTORY_SERVER_HOSTNAME@@\H(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\Indun_NpcServer\Quest\ConditionTable.Bin` |
| **Тип** | правка ДАННЫХ (исполняемый образ не трогается) |
| **Рестарт** | ДА — таблица читается один раз при старте (`sub_421360`) |
| **Разбор** | [`Reports/quest_level_gate.md`](../../../reports/quest_level_gate.md) |

---

## ЗАЧЕМ

Симптом: персонаж 40 уровня (GM_Rimy) не мог взять ни одно низкоуровневое задание — сервер
отвечал 5044 с кодом **11**, клиент показывал нотис 6188 «При сопоставлении уровней произошла
ошибка». Повторялось у NPC 35 (квест 34, уровень 17…24), NPC 34 (квест 11, 7…14),
NPC 31 (квест 19, 7…14).

Диагноз: это НЕ поломка. У заданий в оригинале есть и нижняя, и **верхняя** граница уровня.
`NpcServer!sub_41FD70` @0x41FD70:

```c
if ( (_BYTE)a13 == 1 )                      // cond+36 — «проверять уровень»
{
  if ( !BYTE1(a13) || BYTE2(a13) > 0x96u || (v33 = *(_BYTE *)(a2 + 30858)) == 0 || v33 > 0x96u )
    { sub_408DC0("CheckCondition() CheckLevel Exception...!…"); return 10; }
  if ( BYTE1(a13) > v33 || BYTE2(a13) < v33 )
    return 11;                              // min > уровень  ИЛИ  max < уровень
}
```
где `a13 = *(int*)&cond[36]` ⇒ `+36` флаг, **`+37` min**, **`+38` max**, `+39` флаг класса.

Решение владельца 2026-08-23: **верхнюю границу снять**, нижнюю оставить.

---

## ЧТО

У каждой записи `ConditionTable.Bin` (146 б) с `+36 == 1` и `+38 < 150` байт `+38` поднимается
до **150 (0x96)**. Байт `+37` не трогается.

* тронуто записей: **319** из 1108;
* изменённых байт: **319**, все на смещении `запись*146 + 38`, все стали `0x96`;
* размер файла не меняется — 161 768 б.

| Файл | MD5 |
|---|---|
| оригинал (живой, обе копии одинаковы) | `8cbe9e3c86674368e44eca5da1efbbcb` |
| подготовленный | `158e32bce47d3cc501e4a1d4b3e14291` |

**Почему именно 150.** Это не выдумка: `sub_41FD70` бракует запись, если `max > 0x96` (=150) —
то есть 150 это максимум, принимаемый сервером. И это же значение авторы данных используют как
«потолка нет»: у 487 из 806 записей с проверкой уровня `max` уже равен 150.

Эффект (369 заданий, выдаваемых NPC):

| Уровень | проходит ДО | проходит ПОСЛЕ | «рано» (не меняется) | «перерос» |
|---|---|---|---|---|
| 15 | 38 | 66 | 303 | 28 → 0 |
| **40** | **63** | **290** | **79** | 227 → 0 |
| 60 | 45 | 299 | 70 | 254 → 0 |
| 140 | 105 | 359 | 10 | 254 → 0 |

---

## ПОЧЕМУ ДАННЫЕ, А НЕ ПАТЧ В DLL

* Граница лежит в таблице; код лишь сравнивает. Правка данных обратима возвратом файла из бэкапа,
  не трогает `.text`, не требует площадки в `AsdaPatch.dll` и не участвует в `VerifyAllSites`.
* Патч кода пришлось бы вешать на `sub_41FD70` — общую функцию всех условий (класс, цепочки
  квестов, предметы, кулдаун); снимать в ней ветку рискованнее.
* Значение 150 оставляет данные валидными по собственным правилам сервера.

---

## БЛАСТ-РАДИУС (проверено по дизассемблеру)

* `+37/+38` читает ТОЛЬКО `sub_41FD70`.
* `sub_41FD70` зовётся ровно из двух мест: `sub_421020` (приём, 7101→7102) и `sub_420C10`
  (сдача, 7103→7104).
* **Из 319 условий с потолком ни одно не используется слотами «ПРИНИМАЕТ»** ⇒ сдача заданий
  не затрагивается вообще.
* У каждого слота «ВЫДАЁТ» ровно один индекс условия ⇒ эффекта «взялось другое из пяти» нет.
* `GameServer.exe` эти таблицы не читает (grep по `ConditionTable`/`QuestNpcTable` — пусто).
* `MonsterConditionTable.Bin` (269 × 59 б) в `sub_41FD70` не попадает — не затронута.

---

## ГДЕ ФАЙЛЫ

```
AstoryServer/Docs/NpcServer/patch_quest_level_cap.py      — скрипт-генератор
AstoryServer/Docs/NpcServer/out/ConditionTable.orig.Bin   — копия оригинала (для сверки)
AstoryServer/Docs/NpcServer/out/ConditionTable.Bin        — ГОТОВЫЙ файл
```

Пересобрать при необходимости:
`python AstoryServer/Docs/NpcServer/patch_quest_level_cap.py`

---

## КАК ПРИМЕНИТЬ (выполняет владелец)

```cmd
set V=\\@@ASTORY_SERVER_HOSTNAME@@\H(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2
set SRC=@@ASTORY_DEV_ROOT@@\AstoryServer\Docs\NpcServer\out\ConditionTable.Bin

rem 1) БЭКАП обеих копий
copy "%V%\NpcServer\Quest\ConditionTable.Bin"       "%V%\NpcServer\Quest\ConditionTable.Bin.bak_levelcap_20260823"
copy "%V%\Indun_NpcServer\Quest\ConditionTable.Bin" "%V%\Indun_NpcServer\Quest\ConditionTable.Bin.bak_levelcap_20260823"

rem 2) ПОДМЕНА
copy /Y "%SRC%" "%V%\NpcServer\Quest\ConditionTable.Bin"
copy /Y "%SRC%" "%V%\Indun_NpcServer\Quest\ConditionTable.Bin"

rem 3) сверить MD5 = 158e32bce47d3cc501e4a1d4b3e14291
certutil -hashfile "%V%\NpcServer\Quest\ConditionTable.Bin" MD5

rem 4) РЕСТАРТ NpcServer и Indun_NpcServer
```

⚠ Подменять **обе** копии: файлы у `NpcServer` и `Indun_NpcServer` идентичны (MD5 совпадают), и
если пропатчить только одну — в подземельях поведение разъедется.

## КАК ОТКАТИТЬ

```cmd
copy /Y "%V%\NpcServer\Quest\ConditionTable.Bin.bak_levelcap_20260823"       "%V%\NpcServer\Quest\ConditionTable.Bin"
copy /Y "%V%\Indun_NpcServer\Quest\ConditionTable.Bin.bak_levelcap_20260823" "%V%\Indun_NpcServer\Quest\ConditionTable.Bin"
```
и рестарт тех же двух процессов. MD5 после отката должен стать `8cbe9e3c86674368e44eca5da1efbbcb`.

---

## СВЯЗАННОЕ (клиент)

Клиентская половина правки — в порту, а не здесь (клиентские правки в этот реестр не идут):
`UAsdaQuestMarkerSubsystem::CheckLevel` поднимает потолок до 150 тем же способом.
Ключ отката: консольная переменная `Asda.Quest.LevelCapEnforce 1`.
Без неё клиент прятал бы в облачке NPC 246 записей `SNQICT.Bin` и спорил с сервером.

## РИСКИ

* Осознанное отступление от оригинала: в оригинале потолок есть. Отката два — файл из бэкапа
  (сервер) и `Asda.Quest.LevelCapEnforce 1` (клиент).
* Баланс: высокоуровневый персонаж теперь может добрать награды и опыт низкоуровневых цепочек.
  Это и есть желаемое поведение, но это изменение экономики, а не только UI.
