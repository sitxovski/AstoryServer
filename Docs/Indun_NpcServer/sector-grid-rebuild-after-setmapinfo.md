# Indun_NpcServer — пересборка сетки секторов после `SetMapInfo` (тот же патч, что и в main)

- **Дата:** 2026-08-03
- **Статус:** ✅ ПРИМЕНЁН (ожидает рестарта стойки)
- **Файл:** `\\@@ASTORY_SERVER_HOSTNAME@@\h(@@ASTORY_SERVER_HOSTNAME@@_ns)\ASDA\Working_ASDA\v2\Indun_NpcServer\NpcServer.exe`
- **Тип:** бинарный патч (code-cave)

Полное описание дефекта, разбор формулы соседей, байты и адреса —
в записи main-процесса: [`NpcServer/sector-grid-rebuild-after-setmapinfo.md`](../NpcServer/sector-grid-rebuild-after-setmapinfo.md).

Здесь — только специфика Indun-копии:

- Бинарь **не идентичен** main-копии (58 различающихся байт: другой патч имён
  waitable-таймеров), но код в точке хука и в cave-зоне идентичен байт-в-байт;
  патчер сверял оригинальные байты `E8 0E 24 FC FF` @`0x4582AD` и нулевую
  cave-зону перед записью.
- Патч применён теми же адресами: cave @VA `0x464960` (файл-офсет `0x64960`), 314 байт;
  `call 0x41A6C0` @`0x4582AD` → `call 0x464960`.
- MD5: `4EBE81875921176AD26CECE802458669` → **`C1B28FC077F180F720B9EAE8830C624A`** (516 096 байт).
- Бэкап: `Indun_NpcServer\NpcServer.exe.prefix_neighbors_20260803`.
- Откат: `_dbg\rollback_gridfix_20260803.bat` (возвращает обе копии).
- Рестарт стойки обязателен.
