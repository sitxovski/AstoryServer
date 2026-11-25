# Портал SunnyCoast → t_Castle_of_chess (искажённый шахматный замок)

- **Дата:** 2026-08-25
- **Статус:** применено на живом сервере (файл конфигурации), ТРЕБУЕТ ПЕРЕЗАПУСКА GameServer
- **Процесс/файл:** `GameServer\PortalIP_Info\SunnyCoast_PortalConfig.Ini`
- **Тип:** правка конфигурации (не бинарная)
- **Откат:** вернуть `SunnyCoast_PortalConfig.Ini.bak_t_castle_20260825` (лежит рядом)
## 2026-08-25 — портал в искажённый шахматный замок (SunnyCoast → t_Castle_of_chess)

**Файл:** `GameServer\PortalIP_Info\SunnyCoast_PortalConfig.Ini`
**Резервная копия:** `SunnyCoast_PortalConfig.Ini.bak_t_castle_20260825` (рядом).

Разбор: во всём мире 62 портала, и НИ ОДИН не вёл в карты 10/11 (`t_Palace_of_Queen`,
`t_Castle_of_chess`) — проверено перебором поля `Index` по всем `*_PortalConfig.Ini`, а не по
комментариям. Выход из этих зон при этом есть (`T_Castle_of_Chess` → SunnyCoast,
`T_Palace_of_Queen` → Conquester), точка прибытия в общем справочнике `Total_PortalConfig.Ini`
задана и помечена рабочей (`Use = 1`, 77/70). То есть зона поднята, но входа не существовало.

Добавлено (`count` 1 → 2):

```
//t_Castle_of_chess
[PORTAL_INFO_1]
Index = 11            ; номер карты назначения (MapInfo.ini ServerName_011)
POSX = 67 · POSZ = 273        ; площадка — координаты владельца
RANGEX = 2 · RANGEZ = 4       ; как у парного выхода T_Castle_of_Chess → SunnyCoast
STARTPOSX = 77 · STARTPOSZ = 70   ; точка прибытия из Total_PortalConfig.Ini
INDUN = 0
```

Почему именно там: парный выход из `T_Castle_of_Chess` ставит игрока в SunnyCoast на 72/273 —
вход рядом, на 67/273.

⚠ Подействует ПОСЛЕ перезапуска GameServer. Клиент правки не требует: площадку держит сервер,
переход идёт пакетом 5055. Уровни `t_castle_of_chess` и `t_palace_of_queen` в проекте есть.
⚠ В графе переходов порта (`AsdaQuestTracker.cpp`, `kPortalGraph`) этого ребра нет — на сам переход
не влияет, но автопоход к целям заданий в искажённой зоне маршрут туда не проложит.
