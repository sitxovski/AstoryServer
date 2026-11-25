# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p91b.py — ВЫКЛАДКА / ОТКАТ второй партии данных волны exprate (решение владельца 26.10, после P91):
#   Monster.ai во ВСЕХ 4 папках — опыт двух именных чемпионов Inferion: 840 «Death Champion Drusnan» и 841 «Death Visitor
#   Kalderas» (ур. 72) 1 → 4200 = босс ×20 × F(72) 210 (F(72) — шаг стока +5: 69 → 195, 70 → 200, 71 → 205; генератор и
#   проверка — tools/p91_monster_exp.py validate / apply-b; файлы — tools/data_p91b/…). Меняется только поле +0x35 у 2 записей.
#   База — файлы ПОСЛЕ P91 (выложены 26.10 16:01). DLL не меняются.
#   Разбор: Reports/exprate/MOB_EXP_AUDIT.md §9.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_p91b.py --expect P91_ExpCapRate
#     (expect — контроль, что GameServer поднялся с P91; сам скрипт DLL не трогает); после старта:
#     python deploy_p91b.py --check-started
# Выкладка (--apply; стойка ОСТАНОВЛЕНА): сверка md5 базы в каждой папке → бэкап (<файл>.bak_20261026_p91b рядом,
#   v2\_backup\2026-10-26_p91b\…, @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_exprate\server_p91b\v2\…) → заливка через временный файл
#   со сверкой md5. Файл, уже равный новому, пропускается; чужой md5 — СТОП, код 8, ничего не тронуто.
# Откат (--rollback; стойка остановлена): каждый файл, который сейчас = новый, — из <файл>.bak_20261026_p91b (= база P91).
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/PLAN.md §5
import deploy_p91 as base                                              # общие функции (SSH, бэкап, заливка) — без побочных эффектов
from deploy_p90 import rmd5, rbusy, rcopy, md5

V2 = base.V2
DATA = os.path.join(HERE, "data_p91b")
AI = {   # путь на стойке → (локальный новый, md5 базы после P91, md5 нового)
    r"NpcServer\Monster\Monster.ai":                 ("NpcServer/Monster/Monster.ai", "b05d93eac22cccf12f6c691b87ca57fa", "c4da0022f45ac5dec75e0309246fb0e6"),
    r"Indun_NpcServer\Monster\Monster.ai":           ("Indun_NpcServer/Monster/Monster.ai", "b05d93eac22cccf12f6c691b87ca57fa", "c4da0022f45ac5dec75e0309246fb0e6"),
    r"GameServer\MonsterData_Info\Monster.ai":       ("GameServer/MonsterData_Info/Monster.ai", "b05d93eac22cccf12f6c691b87ca57fa", "c4da0022f45ac5dec75e0309246fb0e6"),
    r"Indun_GameServer\MonsterData_Info\Monster.ai": ("Indun_GameServer/MonsterData_Info/Monster.ai", "4fbe4d914ef1215736d542073e376103", "08c20c9605369dc97fb7145730cde863"),
}
BUSY = [r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe", r"NpcServer\NpcServer.exe", r"Indun_NpcServer\NpcServer.exe"]
AI = stack_layout.expand_paths(AI)        # 26.10: + Ch2_NpcServer / Ch2_GameServer (значения поля — копия побайтная)
BUSY = stack_layout.expand_list(BUSY)

# Свои пути бэкапа и журнала — подменяются в общем модуле до вызова backup_one/put.
base.SUFFIX = ".bak_20261026_p91b"
base.SRV_BACKUP = V2 + r"\_backup\2026-10-26_p91b"
base.LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-26_exprate/server_p91b/v2"
base.LOG = os.path.join(HERE, "run_p91b_20261026_deploy", "deploy.log")
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
    log(lines, "== deploy_p91b %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                        "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    try:
        if check:   # только чтение: md5 четырёх файлов = новый
            good = True
            for rel, (local, b, new) in AI.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый (840/841 = 4200)" if got == new else "база P91 (840/841 = 1)" if got == b else "ЧУЖОЙ!"))
                good = good and got == new
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "процессов стойки работает: %d из %d" % (len(busy), len(BUSY)))
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
            todo = [rel for rel, (l, b, new) in AI.items() if rmd5(V2 + "\\" + rel) == new]
            if not todo:
                log(lines, "СТОП: на стойке нет файлов p91b — откатывать нечего")
                flush(lines)
                return 9
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + base.SUFFIX)
                if bak != AI[rel][1]:
                    log(lines, "СТОП: %s%s нет или это не база P91 (%s)" % (rel, base.SUFFIX, bak))
                    flush(lines)
                    return 6
            for rel in todo:
                rcopy(V2 + "\\" + rel + base.SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got == AI[rel][1] else "НЕ СОШЛОСЬ"))
                if got != AI[rel][1]:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (840/841 снова опыт 1). Нужен старт стойки.")
            flush(lines)
            return 0
        plan = []
        for rel, (local, b, new) in AI.items():
            lp = os.path.join(DATA, local)
            if not os.path.exists(lp) or md5(lp) != new:
                log(lines, "СТОП: %s нет или md5 не %s (перегенерировать: p91_monster_exp.py apply-b)" % (lp, new))
                flush(lines)
                return 3
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == new else new))
            if cur == new:
                continue
            if cur != b:
                log(lines, "СТОП: %s = %s, ожидалась база P91 %s — ничего не трогаю" % (rel, cur, b))
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
        log(lines, "ГОТОВО: Monster.ai (840/841 = 4200) выложены в %d папках. Старт стойки — за координатором; затем "
                   "python deploy_p91b.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
