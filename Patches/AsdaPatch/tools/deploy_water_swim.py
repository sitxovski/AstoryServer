# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_water_swim.py — ВЫКЛАДКА / ОТКАТ «открытой воды» (плавание; задача владельца 28.10.2026): в GameServer
#   `MapData_Info\<MapInfo-имя>.sim` (u32 на клетку, бит 0 = непроходимо; загрузка sub_419E50, проверка sub_41A010 —
#   MoveSyncProcess, навыки, удары, P57) у тайлов открытой воды и берега-спуска снят БИТ 0; прочие биты и клетки не тронуты.
#   Маска — единый источник `AstoryClient/Tools/asda_water_swim.py` (тот же список пишется в клиент `DA_WalkGrid.SwimBits`);
#   файлы — tools/data_water_swim/GameServer/MapData_Info/… (`asda_water_swim.py --make-sims <база> <вывод>`).
#   8 карт: Alpen, LostValley (nightvalley), Rein, Sillaris (silalis), StagnantDesert, SunnyCoast (океан — 30 % от берега),
#   battlefield, flabis. Лава (Mountain Flamion, Castle_of_Chaos, DragonLaiR, firewayforest, Inferion) не открыта.
#   NpcServer `Map\*.SIM` НЕ меняется: мобы в воду не ходят. DLL не меняются. Отчёт: Reports/water_swim/REPORT.md.
#   ★ Выкладка и рестарт: python restart_stack.py --deploy deploy_water_swim.py --expect P57_MoveGuard (expect — контроль
#     старта GameServer); после старта: python deploy_water_swim.py --check-started
# Выкладка (--apply; стойка ОСТАНОВЛЕНА): сверка md5 базы в каждой папке (GameServer, Indun_GameServer, Ch2_GameServer —
#   stack_layout) → бэкап (<файл>.bak_20261028_swim рядом, v2\_backup\2026-10-28_water_swim\…,
#   @@ASTORY_DEV_ROOT@@\_backup\2026-10-28_water_swim\server\v2\…) → заливка через временный файл со сверкой md5.
#   Файл, уже равный новому, пропускается; чужой md5 — СТОП, код 8, ничего не тронуто.
# Откат (--rollback; стойка остановлена): каждый файл, который сейчас = новый, — из <файл>.bak_20261028_swim.
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
_SIMS = {   # имя файла → (md5 базы, md5 нового)
    "Alpen.sim":          ("4fc536aaf0b15cf09becec3e6efd8315", "dcfcca16c1d81103f7888f7f87d74ef1"),
    "LostValley.sim":     ("78212c62754fc39b5d5d1f8c01208da9", "effed70ff7369ea17ab2081dc9b130d1"),
    "Rein.sim":           ("ac4aa4956b42bcff067f228e6ad4f1b4", "9a934792f8e462d63b7883085f73a3bf"),
    "Sillaris.sim":       ("09655ff6336a91127b183d5725fd0cd5", "5c6ecf6c39cd514757be4e40c94c3276"),
    "StagnantDesert.SIM": ("5b05d90bd484d4dac920d9f0f99f9f86", "f9ec2e5d69d0cf139812ea6e411dc946"),
    "SunnyCoast.sim":     ("0fa95d827f2235e937a9ed7198e3b6f2", "eb80788bde710d69e006029caddc151b"),
    # ★ 31.10.2026: battlefield.SIM ИСКЛЮЧЁН (решение владельца — на поле «Битвы армий» в воду не входить): возвращён к базе
    #   скриптом deploy_water_swim_bf_close.py (база 0e02ceed…, открытая 28.10 — d92bb9b7…); здесь больше не выкладывается.
    "flabis.SIM":         ("b4dbef291994f131ee1a39ef662204c1", "36a377321294b8b821eb668ea42edc4c"),
}
# путь на стойке → (локальный новый, md5 базы, md5 нового); Indun — та же база (сверено dry-run), Ch2 — копия поля.
SIM = {}
for _gs in ("GameServer", "Indun_GameServer"):
    for _f, (_b, _n) in _SIMS.items():
        SIM[_gs + "\\MapData_Info\\" + _f] = ("GameServer/MapData_Info/" + _f, _b, _n)
BUSY = [r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe"]
SIM = stack_layout.expand_paths(SIM)      # + Ch2_GameServer (значения поля — копия побайтная)
BUSY = stack_layout.expand_list(BUSY)

# Свои пути бэкапа и журнала — подменяются в общем модуле до вызова backup_one/put.
base.SUFFIX = ".bak_20261028_swim"
base.SRV_BACKUP = V2 + r"\_backup\2026-10-28_water_swim"
base.LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-28_water_swim/server/v2"
base.LOG = os.path.join(HERE, "run_water_swim_20261028_deploy", "deploy.log")
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
    log(lines, "== deploy_water_swim %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                              "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    try:
        if check:   # только чтение: md5 всех файлов = новый, процессы GameServer работают
            good = True
            for rel, (local, b, new) in SIM.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый (вода открыта)" if got == new else "база (вода — блок)" if got == b else "ЧУЖОЙ!"))
                good = good and got == new
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "процессов GameServer работает: %d из %d" % (len(busy), len(BUSY)))
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
                log(lines, "СТОП: %s нет или md5 не %s (перегенерировать: asda_water_swim.py --make-sims)" % (lp, new))
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
        log(lines, "ГОТОВО: .sim с открытой водой выложены (%d файлов). Старт стойки — restart_stack; затем "
                   "python deploy_water_swim.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
