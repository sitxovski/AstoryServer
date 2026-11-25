# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_water_swim_npc2.py — ВЫКЛАДКА / ОТКАТ версии 2 «мобам только мелководье» (баг владельца 28.10: Клевун посреди озера Rein).
#   Поверх версии 1 (deploy_water_swim_npc.py, мелководье открыто) в NpcServer `Map\*.SIM` мобам ЗАКРЫТА вся глубокая вода (не лава):
#   бит 0 взведён у клеток, где поверхность − нижний угол земли > 100, даже если в стоке они были проходимы (Rein: кромка озера
#   глубиной до 229 проходима в стоке — туда по спирали `sub_41AC10` вставали Клевуны 17/18, чьи точки спавна стоят в озере).
#   Маска — `asda_water_swim.py` (`mob_close`); файлы — tools/data_water_swim/NpcServer_v2/Map/… Отчёт: Reports/water_swim/REPORT.md.
#   ★ Выкладка: python restart_stack.py --deploy deploy_water_swim_npc2.py --expect P56_CombatLimits; после — --check-started.
# Бэкап версии 1: <файл>.bak_20261028_swimnpc2 рядом, v2\_backup\2026-10-28_water_swim_npc2\…, @@ASTORY_DEV_ROOT@@\_backup\2026-10-28_water_swim\server_npc2\v2\…
# Откат (--rollback; стойка остановлена): к версии 1 из .bak_20261028_swimnpc2; полный откат к стоку — затем deploy_water_swim_npc.py --rollback.
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
_SIMS = {   # имя файла → (md5 базы = версия 1 мелководья, md5 нового = версия 2: + глубокая вода закрыта мобам)
    "Rein.SIM": ("a90bb33915e5827f142fef4711195eaa", "6f59cba1ab1dc7aeb42a84a38db92d1d"),
    "Sillaris.SIM": ("bc01ca79c088a183962b504d12c7bff5", "946e67668b8740ca0206b32b5507a2be"),
    "StagnantDesert.SIM": ("3e6cf706959a857f918c9f536f5c8e2e", "43f23ecfaffb6da86aa2585a685db5e1"),
    "alpen.SIM": ("f9b7f543347191439c9a3745dc507088", "684e17a125db6fbceca6870509d7e44e"),
    # ★ 31.10.2026: battlefield.SIM ИСКЛЮЧЁН (решение владельца — на поле «Битвы армий» вода закрыта всем, мобам тоже, как в оригинале):
    #   возвращён к стоку 61800215… скриптом deploy_water_swim_bf_close.py; здесь больше не выкладывается.
    "flabis.SIM": ("591f50f39a1f3de982705333a825261e", "937fdfee8185d8723d80918af60b850d"),
    "lostvalley.SIM": ("336079f440794595ab40361bb1b9ee65", "03f2dc80d81d0f267fb63ad4f0433ba4"),
    "sunnycoast.SIM": ("2db042103105b82f6b8e71c71ab97b6e", "f46dd01f934672ec89bbbeb3d19b7de7"),
}
# путь на стойке → (локальный новый, md5 базы, md5 нового); Indun — та же база (сверка dry-run), Ch2 — копия поля.
SIM = {}
for _ns in ("NpcServer", "Indun_NpcServer"):
    for _f, (_b, _n) in _SIMS.items():
        SIM[_ns + "\\Map\\" + _f] = ("NpcServer_v2/Map/" + _f, _b, _n)
BUSY = [r"NpcServer\NpcServer.exe", r"Indun_NpcServer\NpcServer.exe"]
SIM = stack_layout.expand_paths(SIM)      # + Ch2_NpcServer (значения поля — копия побайтная)
BUSY = stack_layout.expand_list(BUSY)

# Свои пути бэкапа и журнала — подменяются в общем модуле до вызова backup_one/put.
base.SUFFIX = ".bak_20261028_swimnpc2"
base.SRV_BACKUP = V2 + r"\_backup\2026-10-28_water_swim_npc2"
base.LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-28_water_swim/server_npc2/v2"
base.LOG = os.path.join(HERE, "run_water_swim_npc2_20261028_deploy", "deploy.log")
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
    log(lines, "== deploy_water_swim_npc2 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                              "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    try:
        if check:   # только чтение: md5 всех файлов = новый, процессы GameServer работают
            good = True
            for rel, (local, b, new) in SIM.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый (v2: глубокая вода закрыта мобам)" if got == new else "база (вода — блок)" if got == b else "ЧУЖОЙ!"))
                good = good and got == new
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "процессов NpcServer работает: %d из %d" % (len(busy), len(BUSY)))
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
        log(lines, "ГОТОВО: .sim NpcServer v2 выложены (%d файлов). Старт стойки — restart_stack; затем "
                   "python deploy_water_swim_npc2.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
