# GameServer — нет верхней границы у индекса сектора в рассылках (НЕ пропатчено)

> **🔄 РЕАЛИЗУЕТСЯ В DLL (2026-08-04).** Guard ставится не бинарным патчем, а
> `AsdaPatch.dll`, секция ini `[P10_SectorIndexBoundsGuard]` (этап 6) — с возможностью
> выключить одним флагом без пересборки. Схема: [`dll-loader-and-patches.md`](dll-loader-and-patches.md).


- **Дата:** 2026-08-03
- **Статус:** 📋 НЕ ПРИМЕНЁН (описание + готовый рецепт). Источник проблемы устранён со стороны NpcServer.
- **Процесс / файл:** `GameServer\GameServer.exe` (и `Indun_GameServer\GameServer.exe`)
- **Тип:** кандидат на бинарный патч (bounds-guard)

## ЧТО не так

`Send_SectorInAddMonsterInfo` @`0x41DE10` (`RE/ida/server_work/GameServer.c:13141`):

```c
if ( a2 >= 0 )                       // ← проверяется ТОЛЬКО нижняя граница
{
  for ( i = 0; i < 9; ++i )
    if ( *(_DWORD *)(*((_DWORD *)this->parentWorldPtr->m_pcSectorMng->ppSector + a2) + 4*i + 20) )
      ...
}
```

`ppSector` — массив на `m_SectorCount` указателей (`sub_46ED30` @`0x46ED30` выделяет
`operator new(4 * Count)`). Верхняя граница `a2 < Count` не проверяется нигде на пути.
Тот же шаблон — в `Send_SectorInNewAddMonsterInfo` @`0x4250A0`.

Последствие: индекс сектора больше `Count` → чтение указателя за границей кучи →
разыменование мусора. Это реальный кандидат на «внезапный» крэш GameServer.

## Откуда брались завышенные индексы (устранено 2026-08-03)

NpcServer писал мобу в `+30400` (`m_SectorIndex`, именно оно уходит в пакеты) значение
`sector->m_Index` от **прошитой** сетки 18×18 (диапазон 0..323), тогда как у GameServer
при секторе 64 всего 64 сектора, при 256 — всего 4. После патча
[`NpcServer/sector-grid-rebuild-after-setmapinfo.md`](../NpcServer/sector-grid-rebuild-after-setmapinfo.md)
`m_Index` пересобирается по фактическому конфигу и совпадает с индексом, посчитанным
из координат, т.е. **источник значений вне диапазона исчез**.

## Почему guard всё-таки НЕ ставился сейчас

GameServer — самый критичный процесс стойки; проверить патч на живом трафике сегодня
нельзя (стойка стоит, замеров нет). Правка двух бинарей за один заход без возможности
теста повышает риск. Ставить отдельно и осознанно, когда будет окно.

## Рецепт (если ставить)

1. Cave в хвосте `.text` GameServer.exe (по аналогии с NpcServer: зона нулей за
   `VirtualSize`, но внутри `SizeOfRawData`).
2. Заменить проверку `if (a2 >= 0)` на `if ((unsigned)a2 < (unsigned)m_SectorCount)`:
   `m_SectorCount` = `[m_pcSectorMng + 0x0C]` (поле `this+3` в `sub_46ED30`).
   Беззнаковое сравнение закрывает обе границы одной инструкцией.
3. Сделать то же в `Send_SectorInNewAddMonsterInfo` @`0x4250A0`.
4. Бэкап `GameServer.exe.presectorguard_YYYYMMDD`, отдельная запись в реестре, рестарт.

## Заметка «в плюс»

`AddMonster` @`0x46DEF0` у GameServer, в отличие от NpcServer, лимит `MAX_SECTOR_MONSTER`
(200) проверяет и логирует (`AddMonster() if( MAX_SECTOR_MONSTER <= m_iLastMonsterDirectArray )`).
Это удобный индикатор при секторе 256 — см. `_Common/aoi-sector-size-256-after-gridfix.md`.
