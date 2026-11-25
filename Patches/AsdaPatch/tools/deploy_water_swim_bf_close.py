# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_water_swim_bf_close.py — ★ 31.10.2026 ЗАКРЫТЬ ВОДУ НА ПОЛЕ БИТВЫ (карта 19 battlefield, «Битва армий»; РЕШЕНИЕ ВЛАДЕЛЬЦА
#   после отзыва игроков «you shouldn't be able to go in water»: «закрыть всем, мобам тоже, как в оригинале»). [ОРИГИНАЛ]
#   У оригинала плавания нет вовсе: вода — непроходимый тайл (клиент .TER бит 0, сервер .SIM бит 0); RE_SPEC campwar_bugs §3.
#   28.10 файл `battlefield.SIM` менялся на стойке:
#     • GameServer (`MapData_Info\`) — `deploy_water_swim.py`: снят бит 0 у 63 997 водных тайлов (сток 0e02ceed… → d92bb9b7…);
#     • NpcServer (`Map\`) — `deploy_water_swim_npc.py`: мобам открыто мелководье, 10 141 клетка (сток 61800215… → v1 4bb421d1…),
#       затем `deploy_water_swim_npc2.py`: мобам закрыта глубокая вода (→ v2 6959ef09…).
#     ★ Прежний комментарий этого скрипта «NpcServer не менялся и 28.10» был НЕВЕРЕН (поправка 31.10).
#   Здесь ТОЛЬКО `battlefield.SIM` во всех папках стойки — GameServer, Indun_GameServer, Ch2_GameServer, NpcServer, Indun_NpcServer,
#   Ch2_NpcServer (stack_layout) — возвращается к СТОКУ (побайтно исходные файлы сервера). Остальные 7 карт с открытой водой не
#   трогаются. Клиент — та же маска: генератор `AstoryClient/Tools/asda_water_swim.py` исключает battlefield (`EXCLUDE`),
#   `DA_WalkGrid.SwimBits` карты 19 очищен (`asda_export_swimbits.py`). DLL и протокол не меняются.
# Источник стока — локальные копии бэкапов 28.10 (md5 сверяется): GameServer — `@@ASTORY_DEV_ROOT@@\_backup\2026-10-28_water_swim\server\v2\
#   <папка>\MapData_Info\battlefield.SIM`, NpcServer — `…\server_npc\v2\<папка>\Map\battlefield.SIM`.
#   Бэкап текущего — рядом `.bak_20261031_bfclose`, `v2\_backup\2026-10-31_campwar_water\…`, локально
#   `@@ASTORY_DEV_ROOT@@\_backup\2026-10-31_campwar_bugs\server\v2\…`.
# Выкладка (--apply; стойка ОСТАНОВЛЕНА): python restart_stack.py --deploy deploy_water_swim_bf_close.py --expect P57_MoveGuard;
#   после старта — python deploy_water_swim_bf_close.py --check-started. Сухой прогон — без ключей.
# Откат (--rollback; стойка остановлена): файл, который сейчас = сток, — из `.bak_20261031_bfclose` (версия 28.10).
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
import deploy_p91 as base                                              # общие функции (SSH, бэкап, заливка) — без побочных эффектов
from deploy_p90 import rmd5, rbusy, rcopy, md5

V2 = base.V2
FILE = "battlefield.SIM"                                       # MapInfo-имя карты 19 (asda_map_registry → .sim сервера)
LOCAL = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-28_water_swim"            # локальные бэкапы 28.10 (сток)
# Сток и допустимые «открытые» версии 28.10 по роду папки.
GS_BASE, GS_OPEN = "0e02ceede36db809a33711f751d6a4ac", ("d92bb9b78d19a258fc5e51fb3ba22adf",)
NS_BASE, NS_OPEN = "6180021513f525b46740afcf3da97329", ("6959ef094c80c2f94a03fe86a7482d42", "4bb421d17a3a309ea554a869980753f6")


def _row(rel):
    """Путь на стойке → (локальный файл стока, md5 стока, допустимые md5 версии 28.10)."""
    top = rel.split("\\")[0]
    if "NpcServer" in top:
        return ("%s/server_npc/v2/%s/Map/%s" % (LOCAL, top, FILE), NS_BASE, NS_OPEN)
    return ("%s/server/v2/%s/MapData_Info/%s" % (LOCAL, top, FILE), GS_BASE, GS_OPEN)


_REL = {"GameServer\\MapData_Info\\" + FILE: 0, "Indun_GameServer\\MapData_Info\\" + FILE: 0,
        "NpcServer\\Map\\" + FILE: 0, "Indun_NpcServer\\Map\\" + FILE: 0}
SIM = {rel: _row(rel) for rel in stack_layout.expand_paths(_REL)}   # + Ch2_GameServer / Ch2_NpcServer
BUSY = stack_layout.expand_list([r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe",
                                 r"NpcServer\NpcServer.exe", r"Indun_NpcServer\NpcServer.exe"])

# Свои пути бэкапа и журнала — подменяются в общем модуле до вызова backup_one/put.
base.SUFFIX = ".bak_20261031_bfclose"
base.SRV_BACKUP = V2 + r"\_backup\2026-10-31_campwar_water"
base.LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-31_campwar_bugs/server/v2"
base.LOG = os.path.join(HERE, "run_water_swim_bf_close_20261031", "deploy.log")
log, flush = base.log, base.flush


def main():
    """Сухой прогон / --apply / --rollback / --check-started. Код 0 — успех."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    check = "--check-started" in sys.argv
    lines = []
    log(lines, "== deploy_water_swim_bf_close %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
        "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    try:
        if check:   # только чтение: все файлы = сток, процессы GameServer/NpcServer работают
            good = True
            for rel, (lp, b, opn) in SIM.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "сток (вода — блок)" if got == b else "версия 28.10 (вода открыта)!" if got in opn else "ЧУЖОЙ!"))
                good = good and got == b
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "процессов GameServer/NpcServer работает: %d из %d" % (len(busy), len(BUSY)))
            ok = good and len(busy) == len(BUSY)
            log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if ok else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
            flush(lines)
            return 0 if ok else 5
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if rollback:
            todo = [rel for rel, (lp, b, opn) in SIM.items() if rmd5(V2 + "\\" + rel) == b]
            for rel in todo:
                if rmd5(V2 + "\\" + rel + base.SUFFIX) not in SIM[rel][2]:
                    log(lines, "СТОП: %s%s нет или это не версия 28.10" % (rel, base.SUFFIX))
                    flush(lines)
                    return 6
            for rel in todo:
                want = rmd5(V2 + "\\" + rel + base.SUFFIX)
                rcopy(V2 + "\\" + rel + base.SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got == want else "НЕ СОШЛОСЬ"))
                if got != want:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (вода поля битвы снова как 28.10, %d файлов). Нужен старт стойки." % len(todo))
            flush(lines)
            return 0
        plan = []
        for rel, (lp, b, opn) in SIM.items():
            if not os.path.exists(lp) or md5(lp) != b:
                log(lines, "СТОП: локального стока %s нет или md5 не %s" % (lp, b))
                flush(lines)
                return 3
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже сток" if cur == b else b))
            if cur == b:
                continue
            if cur not in opn:
                log(lines, "СТОП: %s = %s, ожидалась версия 28.10 %s — ничего не трогаю" % (rel, cur, "/".join(opn)))
                flush(lines)
                return 8
            plan.append((rel, lp, b))
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (%d файлов)" % len(plan))
            flush(lines)
            return 0
        for rel, lp, b in plan:
            base.backup_one(rel, lines)
            base.put(rel, lp, b, lines)
        log(lines, "ГОТОВО: вода поля битвы закрыта (%d файлов). Старт стойки — restart_stack; затем "
                   "python deploy_water_swim_bf_close.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
