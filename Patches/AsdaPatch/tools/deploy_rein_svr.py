# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_rein_svr.py — ВЫКЛАДКА / ОТКАТ: точки спавна Клевунов на Rein из озера на берег (решение владельца 29.10.2026, «да, на берег»).
#   Rein.svr (запись 0x4A: +4 tileX u16, +8 tileZ u16, +0x20 roam [minX,minZ,maxX,maxZ] u32) — idx 5 (96,392)→(85,402),
#   idx 6 (95,395)→(89,404), idx 7 (107,365)→(119,373), idx 8 (105,376)→(116,385); roam расширен до новой точки. Точки — ближайшие
#   сухие проходимые для мобов клетки (NpcServer .SIM v2) с сухой окрестностью 3×3. Файл один для GameServer\MonsterData_Info и
#   NpcServer\Monster (+ Indun, Ch2). Данные — tools/data_water_swim/Rein_svr/Rein.svr. Отчёт: Reports/water_swim/REPORT.md.
#   ★ Выкладка: python restart_stack.py --deploy deploy_rein_svr.py --expect P56_CombatLimits; после — --check-started.
# Бэкап: <файл>.bak_20261029_reinsvr рядом, v2\_backup\2026-10-29_rein_svr\…, @@ASTORY_DEV_ROOT@@\_backup\2026-10-28_water_swim\server_reinsvr\v2\…
# Откат (--rollback; стойка остановлена): из .bak_20261029_reinsvr.
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
import deploy_p91 as base                                              # общие функции (SSH, бэкап, заливка) — без побочных эффектов
from deploy_p90 import rmd5, rbusy, rcopy, md5

V2 = base.V2
DATA = os.path.join(HERE, "data_water_swim")
_SIMS = {"Rein.svr": ("9c027a125fd9f941df44a01e52183aec", "36a450c4c880f1cd40813b6f5c38268a")}   # имя → (md5 базы, md5 нового)
# путь на стойке → (локальный новый, md5 базы, md5 нового); Ch2 — копия поля.
SIM = {}
for _d in ("GameServer\\MonsterData_Info", "Indun_GameServer\\MonsterData_Info", "NpcServer\\Monster", "Indun_NpcServer\\Monster"):
    for _f, (_b, _n) in _SIMS.items():
        SIM[_d + "\\" + _f] = ("Rein_svr/" + _f, _b, _n)
BUSY = [r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe", r"NpcServer\NpcServer.exe", r"Indun_NpcServer\NpcServer.exe"]
SIM = stack_layout.expand_paths(SIM)      # + Ch2_NpcServer (значения поля — копия побайтная)
BUSY = stack_layout.expand_list(BUSY)

# Свои пути бэкапа и журнала — подменяются в общем модуле до вызова backup_one/put.
base.SUFFIX = ".bak_20261029_reinsvr"
base.SRV_BACKUP = V2 + r"\_backup\2026-10-29_rein_svr"
base.LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-28_water_swim/server_reinsvr/v2"
base.LOG = os.path.join(HERE, "run_rein_svr_20261029_deploy", "deploy.log")
log, flush = base.log, base.flush


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    check = "--check-started" in sys.argv
    lines = []
    log(lines, "== deploy_rein_svr %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                              "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    try:
        if check:   # только чтение: md5 всех файлов = новый, процессы GameServer работают
            good = True
            for rel, (local, b, new) in SIM.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый (Клевуны на берегу)" if got == new else "база (вода — блок)" if got == b else "ЧУЖОЙ!"))
                good = good and got == new
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "процессов GameServer/NpcServer работает: %d из %d" % (len(busy), len(BUSY)))
            log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good and len(busy) == len(BUSY) else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
            flush(lines)
            return 0 if good and len(busy) == len(BUSY) else 5
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if rollback:
            todo = [rel for rel, (l, b, new) in SIM.items() if rmd5(V2 + "\\" + rel) == new]
            if not todo:
                log(lines, "СТОП: на стойке нет файлов water_swim — откатывать нечего")
                flush(lines)
                return 9
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + base.SUFFIX)
                if bak != SIM[rel][1]:
                    log(lines, "СТОП: %s%s нет или это не база (%s)" % (rel, base.SUFFIX, bak))
                    flush(lines)
                    return 6
            for rel in todo:
                rcopy(V2 + "\\" + rel + base.SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got == SIM[rel][1] else "НЕ СОШЛОСЬ"))
                if got != SIM[rel][1]:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (вода снова блок). Нужен старт стойки.")
            flush(lines)
            return 0
        plan = []
        for rel, (local, b, new) in SIM.items():
            lp = os.path.join(DATA, local)
            if not os.path.exists(lp) or md5(lp) != new:
                log(lines, "СТОП: %s нет или md5 не %s (перегенерировать: asda_water_swim.py --make-npc-sims)" % (lp, new))
                flush(lines)
                return 3
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == new else new))
            if cur == new:
                continue
            if cur != b:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю" % (rel, cur, b))
                flush(lines)
                return 8
            plan.append((rel, lp, new))
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (%d файлов)" % len(plan))
            flush(lines)
            return 0
        for rel, lp, new in plan:
            base.backup_one(rel, lines)
            base.put(rel, lp, new, lines)
        log(lines, "ГОТОВО: Rein.svr выложен (%d файлов). Старт стойки — restart_stack; затем "
                   "python deploy_rein_svr.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
