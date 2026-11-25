# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p119r.py — P119r: ИСПРАВЛЕНИЕ P119 (09.11.2026, пачка 20, баг 7; сессия flammio-npc). Выложенный 09.11 13:35 P119 дописал 10 NPC
#   Forgotten Canyon (карта 5: 21, 108–115, 177) в Night_Valley.npc — а это файл КАРТЫ 4 (Night Valley).
#   ПРИЧИНА ОШИБКИ. Связь «номер карты → файл NPC» задаёт NpcServer\ini\MapInfo.ini (NonPlayerInfo_004="Night_Valley.npc",
#     NonPlayerInfo_005="LostValley.npc"), а сверка P119 сопоставляла клиентскую папку карты 5 (`nightvalley`) с серверным файлом ПО
#     ИМЕНИ. Второй метод: стоковый Night_Valley.npc = одна запись NPC 22 (npc_list: карта 4); стоковый и живой LostValley.npc УЖЕ
#     содержат все 10 NPC каньона — с сервера они никогда не пропадали (пропадали только в клиенте порта, по той же ошибке построителя).
#   ★ Arshes (NPC 37): сток — Rein.npc (карта 1); P119 добавил её и в Alpen.npc (клиент оригинала перечисляет её в rein.NPC и в alpen.NPC,
#     npc_list — карта 3). Владелец 09.11: «Arshez 37 (in alpen) should be in alpen map, but hidden for players!» — запись в Alpen.npc
#     ОСТАЁТСЯ (это не дубль: две карты), в клиенте в Альпии она только для GM_ с [MISSING]. Alpen.npc этим пакетом не трогается
#     (`build_alpen` оставлена неиспользуемой как разбор варианта «убрать»).
#   ПРАВКА: Night_Valley.npc во всех GameServer (NpcData_Info) и NpcServer (NpcInfo) возвращается к содержимому ДО P119 (база P119 =
#     сток, одна запись NPC 22) — то есть убираются ровно 10 дописанных записей. LostValley.npc и остальные файлы P119 (Alpen, Flammio,
#     firewayforest, Inferion — сверены по MapInfo 003/007/016/018) не трогаются.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_p119r.py
#   python deploy_p119r.py --build   — снимки Night_Valley.npc со стойки (только чтение) → p119r_data/srv_in; сверка: md5 = «новый» P119;
#                                      выход = база P119 (p119_data/srv_in), сверка «выход = вход без последних 10 записей»; манифест, diff
#   python deploy_p119r.py           — сухой прогон; --apply (GameServer и NpcServer ОСТАНОВЛЕНЫ) / --rollback / --check-started —
#                                      тот же поток, что deploy_p119.py (бэкап .bak_<tag>, откат из него).
# Модуль без побочных эффектов при импорте.
import json
import os
import shutil
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки
import deploy_p119 as P                               # снимки, md5, поток выкладки (без побочных эффектов)

DATA = os.path.join(HERE, "p119r_data")               # снимок, выход, манифест этой правки
TAG = "20261109_p119r"                                # суффикс бэкапов стойки .bak_<tag>
FNAME = "Night_Valley.npc"                            # файл карты 4 (MapInfo.ini NonPlayerInfo_004)
WRONG = [21, 108, 109, 110, 111, 112, 113, 114, 115, 177]   # NPC карты 5, ошибочно дописанные P119
REC = 0xDD                                            # длина записи .npc


def build_alpen(p119, files, diff):
    """Alpen.npc: P119 дописал 2, 37, 98, 99; Arshes 37 на стоке стоит в Rein.npc (карта 1) — в Alpen это дубль. Выход = база P119 +
    записи 2, 98, 99 тем же правилом P119 (индексы подряд, тайл/поворот из npc_list, хвост — самый частый по стойке)."""
    table = P.npc_list()
    for d, sub in [(g, "NpcData_Info") for g in stack_layout.GS_FOLDERS] + [(g, "NpcInfo") for g in stack_layout.NPC_FOLDERS]:
        rel = "%s\\%s\\%s" % (d, sub, "Alpen.npc")
        loc_in = os.path.join(DATA, "srv_in", d, sub, "Alpen.npc")
        base = P.scp_get(rel, loc_in)
        if base != p119[rel]["new"]:
            raise SystemExit("ОТКАЗ: %s md5 %s ≠ «новому» P119 %s — файл менялся после P119" % (rel, base, p119[rel]["new"]))
        pre = os.path.join(HERE, "p119_data", "srv_in", d, sub, "Alpen.npc")
        old, add, rows = P.build_records(pre, [2, 98, 99], table, 3)
        cur = open(loc_in, "rb").read()
        tail = cur[len(old):]
        ids = [struct.unpack_from("<I", tail, i * REC + 4)[0] for i in range(len(tail) // REC)]
        if cur[:len(old)] != old or ids != [2, 37, 98, 99]:
            raise SystemExit("ОТКАЗ: %s — живой файл не равен «база P119 + 2, 37, 98, 99» (хвост %s)" % (rel, ids))
        # Сверка: новые записи 2/98/99 байт в байт = записям P119 (кроме индекса 98/99 — сдвиг на одну позицию).
        loc_out = os.path.join(DATA, "srv_out", d, sub, "Alpen.npc")
        os.makedirs(os.path.dirname(loc_out), exist_ok=True)
        with open(loc_out, "wb") as f:
            f.write(old + add)
        new = P.md5(loc_out)
        files[rel] = {"local": os.path.relpath(loc_out, HERE).replace("\\", "/"), "base": base, "new": new}
        diff.append("%s	%s	%s	%d	%s" % (rel, base, new, 1, "37 (дубль Rein)"))
        print("%-46s %s → %s  убрана запись 37 (дубль Rein), 2/98/99 остаются" % (rel, base, new))


def build():
    """Снимки Night_Valley.npc, выход = база P119, сверки, манифест."""
    p119 = json.load(open(os.path.join(HERE, "p119_data", "manifest.json"), encoding="utf-8"))["files"]
    files = {}
    diff = ["file\tbase(после P119)\tnew(до P119)\tубрано записей\tnpc"]
    for d, sub in [(g, "NpcData_Info") for g in stack_layout.GS_FOLDERS] + [(g, "NpcInfo") for g in stack_layout.NPC_FOLDERS]:
        rel = "%s\\%s\\%s" % (d, sub, FNAME)
        if rel not in p119:
            raise SystemExit("ОТКАЗ: %s нет в манифесте P119" % rel)
        loc_in = os.path.join(DATA, "srv_in", d, sub, FNAME)
        base = P.scp_get(rel, loc_in)
        if base != p119[rel]["new"]:
            raise SystemExit("ОТКАЗ: %s md5 %s ≠ «новому» P119 %s — файл менялся после P119" % (rel, base, p119[rel]["new"]))
        pre = os.path.join(HERE, "p119_data", "srv_in", d, sub, FNAME)
        if P.md5(pre) != p119[rel]["base"]:
            raise SystemExit("ОТКАЗ: снимок до P119 %s не совпал с базой манифеста P119" % pre)
        cur, old = open(loc_in, "rb").read(), open(pre, "rb").read()
        # Сверка: живой = база P119 + ровно 10 записей с id WRONG; выход = база P119.
        tail = cur[len(old):]
        ids = [struct.unpack_from("<I", tail, i * REC + 4)[0] for i in range(len(tail) // REC)]
        if cur[:len(old)] != old or len(tail) != REC * len(WRONG) or ids != WRONG:
            raise SystemExit("ОТКАЗ: %s — живой файл не равен «база P119 + 10 записей %s» (хвост %s)" % (rel, WRONG, ids))
        loc_out = os.path.join(DATA, "srv_out", d, sub, FNAME)
        os.makedirs(os.path.dirname(loc_out), exist_ok=True)
        shutil.copyfile(pre, loc_out)
        new = P.md5(loc_out)
        files[rel] = {"local": os.path.relpath(loc_out, HERE).replace("\\", "/"), "base": base, "new": new}
        diff.append("%s\t%s\t%s\t%d\t%s" % (rel, base, new, len(ids), ",".join(map(str, ids))))
        print("%-46s %s → %s  убрано %d записей (%s)" % (rel, base, new, len(ids), ",".join(map(str, ids))))
    # ★ Alpen.npc НЕ трогается: Arshes 37 в Альпии оставлена владельцем («Arshez 37 (in alpen) should be in alpen map, but hidden for
    #   players!») — на сервере она стоит и в Рейне (сток), и в Альпии (P119); в клиенте в Альпии она только для GM_. `build_alpen` не зовётся.
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "diff.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(diff) + "\n")
    man = {"tag": TAG, "patch": "P119r", "files": files}
    with open(os.path.join(DATA, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    print("манифест: %s (файлов %d)" % (os.path.join(DATA, "manifest.json"), len(files)))


def main():
    """--build; иначе поток deploy_p119 по своему манифесту и метке."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        build()
        return 0
    P.DATA = DATA
    P.TAG = TAG
    P.DPB.LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"
    return P.deploy()


if __name__ == "__main__":
    sys.exit(main())
