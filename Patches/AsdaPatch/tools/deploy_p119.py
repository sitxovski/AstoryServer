# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p119.py — P119: НЕДОСТАЮЩИЕ NPC В СЕРВЕРНОЙ РАССТАНОВКЕ (09.11.2026, пачка 20, баг 7 «во Фламмио рядом с волком нет
#   девушки-рыболова»; сессия flammio-npc). Разбор и список — Reports/batch20/flammio_npc/ (missing_npcs.tsv).
#   ПРИЧИНА. NPC в мир выводит только сервер (`LoadNpcInfo` читает NpcData_Info\<Карта>.npc, клиенту уходит 4067). Клиент оригинала
#     перечисляет в map\<карта>\<карта>.NPC 18 NPC, которых нет ни в стоковых (2010), ни в живых .npc стойки: среди них NPC 7
#     «Agnes» — торговка рыбалкой во Фламмио (npc_list: карта 7, X/Z 16400/13700, поворот 90). Серверная таблица лавок NPC.nif
#     id 7 знает — не хватает только расстановки.
#   ПРАВКА (решение владельца 09.11: «Agnes bring back… other missing npc bring back but display only for GM_ users»): в .npc карт
#     ДОПИСЫВАЮТСЯ записи этих NPC (существующие записи байт в байт не меняются). Запись 0xDD: +0 индекс u32 (следующий по порядку),
#     +4 id u32, +8/+A тайл X/Z i16 (= npc_list X/Z // 100), +C поворот u32 (npc_list +0x78), хвост +0x10…+0xDC — самый частый хвост
#     этого же файла (флаги сценариев «пусто»). Видимость «только GM_» — клиентский фильтр (asda.Npc.GmOnly, Config/DefaultGame.ini
#     [AsdaGmOnlyNpcs]); сервер спавнит всех.
#   Охват: Фламмио 7; Альпия 2, 37, 98, 99; Fireway 201; Инферион 200; Ночная долина 21, 108–115, 177 (17 записей в 5 картах).
#   Шахта (202–204) и данж Альпии (22): на стойке у этих карт нет .npc — не входят (согласуется с сессией шахты).
#   Файлы: NpcData_Info\<F>.npc во всех GameServer (stack_layout.GS_FOLDERS) и NpcInfo\<F>.npc во всех NpcServer (NPC_FOLDERS).
#   Читаются при старте процессов — нужен рестарт GameServer и NpcServer. Exe и DLL не меняются.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_p119.py
#   python deploy_p119.py --build      — снимки .npc со стойки по SSH (только чтение) → p119_data/srv_in, дописывание → srv_out,
#                                        манифест md5, diff (p119_data/diff.tsv); сверка «старые записи байт в байт, добавлено ровно N»
#   python deploy_p119.py              — сухой прогон (md5 базы на стойке = манифесту; ничего не пишет)
#   --apply (GameServer и NpcServer ОСТАНОВЛЕНЫ) / --rollback / --check-started — бэкап .bak_<tag> рядом, в v2\_backup и локально
#     (deploy_premium_boxes.backup_one / put), откат из .bak_<tag>.
# Модуль без побочных эффектов при импорте.
import collections
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки (все GameServer и NpcServer)
import deploy_premium_boxes as DPB                    # бэкап/заливка (без побочных эффектов)
from deploy_p90 import rmd5, rbusy, rcopy, md5        # общие функции SSH

DATA = os.path.join(HERE, "p119_data")                # снимок, выход, манифест, diff этой правки
TAG = "20261109_p119"                                 # суффикс бэкапов стойки .bak_<tag>
NPC_LIST = r"@@ASTORY_DEV_ROOT@@\Donors\AsdaChroniclesInterlude\Data\NPC\npc_list.BIN"   # таблица NPC клиента оригинала
SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"        # ключ SSH
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"             # стойка
SRV_ROOT = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"                  # корень стойки (scp)
V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                       # корень стойки (пути манифеста)
REC = 0xDD                                            # длина записи .npc
# Файл карты на стойке → id NPC к дописыванию, с картой npc_list (сверка, что NPC этой карты).
TARGETS = collections.OrderedDict([
    ("Flammio.npc", (7, [7])),
    ("Alpen.npc", (3, [2, 37, 98, 99])),
    ("firewayforest.npc", (16, [201])),
    ("Inferion.npc", (18, [200])),
    ("Night_Valley.npc", (5, [21, 108, 109, 110, 111, 112, 113, 114, 115, 177])),
])
EXPECT_RECORDS = 17                                   # охват по решению владельца: Agnes + 16 под GM-фильтром
DEFAULT_TAIL = [b""]                                  # хвост записи для пустого файла (заполняется первым непустым — Flammio.npc)
BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS] + [d + r"\NpcServer.exe" for d in stack_layout.NPC_FOLDERS]


def scp_get(rel, dst):
    """Снимок файла стойки (только чтение) → dst; возврат md5."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    src = "%s:%s/%s" % (SSH_HOST, SRV_ROOT, rel.replace("\\", "/"))
    p = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", src, dst], capture_output=True, timeout=600)
    if p.returncode != 0:
        raise SystemExit("ОТКАЗ: scp %s: %s" % (rel, p.stderr.decode("utf-8", "replace")[-200:]))
    return md5(dst)


def npc_list():
    """id → (карта, X, Z, поворот, класс) из npc_list.BIN клиента оригинала (запись 0x88 с +0x14)."""
    b = open(NPC_LIST, "rb").read()
    out = {}
    for k in range((len(b) - 0x14) // 0x88):
        r = 0x14 + k * 0x88
        rid = struct.unpack_from("<H", b, r)[0]
        mp = struct.unpack_from("<i", b, r + 0x6C)[0]
        x, z = struct.unpack_from("<ff", b, r + 0x70)
        face, cls = struct.unpack_from("<II", b, r + 0x78)
        out[rid] = (mp, x, z, face, cls)
    return out


def build_records(path_in, ids, table, mapid):
    """Новые записи для ids: хвост — самый частый хвост файла; индекс — следующий; тайл и поворот — из npc_list."""
    b = open(path_in, "rb").read()
    if len(b) % REC:
        raise SystemExit("ОТКАЗ: %s длина %d не кратна 0x%X" % (path_in, len(b), REC))
    n = len(b) // REC
    have = {struct.unpack_from("<I", b, i * REC + 4)[0] for i in range(n)}
    tails = collections.Counter(b[i * REC + 0x10:(i + 1) * REC] for i in range(n))
    # Пустой файл (Inferion на стойке — 0 записей): хвост — самый частый по стойке (169 из 186 записей всех карт), взят из Flammio.npc.
    tail = tails.most_common(1)[0][0] if tails else DEFAULT_TAIL[0]
    if not tail:
        raise SystemExit("ОТКАЗ: %s пуст, а хвоста по умолчанию нет (Flammio.npc должен идти первым)" % path_in)
    if not DEFAULT_TAIL[0]:
        DEFAULT_TAIL[0] = tail
    out, rows = b"", []
    for k, nid in enumerate(ids):
        if nid in have:
            raise SystemExit("ОТКАЗ: %s уже содержит NPC %d" % (path_in, nid))
        mp, x, z, face, cls = table[nid]
        if mp != mapid:
            raise SystemExit("ОТКАЗ: NPC %d в npc_list на карте %d, ждали %d" % (nid, mp, mapid))
        tx, tz = int(x // 100), int(z // 100)
        head = struct.pack("<IIhhI", n + k, nid, tx, tz, face)
        out += head + tail
        rows.append((n + k, nid, cls, tx, tz, face, x, z))
    return b, out, rows


def build():
    """Снимки .npc всех GameServer и NpcServer, дописывание записей, манифест md5, diff."""
    table = npc_list()
    files, total = {}, 0
    diff = ["file\tindex\tnpc\tclass\ttileX\ttileZ\tface\tlist_X\tlist_Z"]
    for fname, (mapid, ids) in TARGETS.items():
        outs = set()
        for d, sub in [(g, "NpcData_Info") for g in stack_layout.GS_FOLDERS] + [(g, "NpcInfo") for g in stack_layout.NPC_FOLDERS]:
            rel = "%s\\%s\\%s" % (d, sub, fname)
            loc_in = os.path.join(DATA, "srv_in", d, sub, fname)
            base = scp_get(rel, loc_in)
            old, add, rows = build_records(loc_in, ids, table, mapid)
            loc_out = os.path.join(DATA, "srv_out", d, sub, fname)
            os.makedirs(os.path.dirname(loc_out), exist_ok=True)
            with open(loc_out, "wb") as f:
                f.write(old + add)
            # Независимая сверка: прежние записи байт в байт, добавлено ровно len(ids) записей.
            got = open(loc_out, "rb").read()
            if got[:len(old)] != old or len(got) != len(old) + REC * len(ids):
                raise SystemExit("ОТКАЗ: %s — прежние записи изменены или длина не та" % loc_out)
            new = md5(loc_out)
            outs.add((base, new))
            files[rel] = {"local": os.path.relpath(loc_out, HERE).replace("\\", "/"), "base": base, "new": new}
            total += len(ids)
            for r in rows:
                diff.append("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%.0f\t%.0f" % ((rel,) + r))
            print("%-50s %s → %s  +%d записей" % (rel, base, new, len(ids)))
    if sum(len(v[1]) for v in TARGETS.values()) != EXPECT_RECORDS:
        raise SystemExit("ОТКАЗ: охват не %d записей" % EXPECT_RECORDS)
    with open(os.path.join(DATA, "diff.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(diff) + "\n")
    man = {"tag": TAG, "patch": "P119", "records": EXPECT_RECORDS, "files": files}
    with open(os.path.join(DATA, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    print("манифест: %s (файлов %d, записей во всех копиях %d)" % (os.path.join(DATA, "manifest.json"), len(files), total))


def rmd5_or_locked(path):
    """md5 файла стойки; "locked" — файл держит работающий процесс эксклюзивно (пустой Inferion.npc у GameServer: Md5Of даёт
    IOException). Строгая сверка такого файла — при --apply/--rollback, когда стойка остановлена."""
    try:
        return rmd5(path)
    except RuntimeError as e:
        if "IOException" in str(e):
            return "locked"
        raise


def log(lines, line):
    """Строка в вывод и в журнал прогона."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать журнал прогона в run_p119_<tag>/deploy.log."""
    p = os.path.join(HERE, "run_p119_%s" % TAG, "deploy.log")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def deploy():
    """Сухой прогон / --apply / --rollback / --check-started по манифесту (GameServer и NpcServer)."""
    apply, rollback, check = "--apply" in sys.argv, "--rollback" in sys.argv, "--check-started" in sys.argv
    man = json.load(open(os.path.join(DATA, "manifest.json"), encoding="utf-8"))
    files = man["files"]
    lines = []
    log(lines, "== deploy_p119 %s %s (метка %s, файлов %d)" % (time.strftime("%Y-%m-%d %H:%M:%S"),
        "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон", TAG, len(files)))
    roots = set(rel.split("\\")[0] for rel in files)
    if roots != set(stack_layout.GS_FOLDERS) | set(stack_layout.NPC_FOLDERS):
        log(lines, "СТОП: манифест покрывает %s, стойка — %s (пересобери: --build)" % (sorted(roots), stack_layout.GS_FOLDERS + stack_layout.NPC_FOLDERS))
        flush(lines)
        return 3
    try:
        if check:
            good = True
            for rel, f in files.items():
                got = rmd5_or_locked(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый" if got == f["new"] else "база" if got == f["base"] else "ЧУЖОЙ!"))
                good = good and got == f["new"]
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "GameServer/NpcServer работают: %d из %d" % (len(busy), len(BUSY)))
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
            todo = [rel for rel, f in files.items() if rmd5(V2 + "\\" + rel) == f["new"]]
            if not todo:
                log(lines, "СТОП: на стойке нет новых файлов — откатывать нечего")
                flush(lines)
                return 9
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + ".bak_" + TAG)
                if bak != files[rel]["base"]:
                    log(lines, "СТОП: %s.bak_%s нет или это не база (%s)" % (rel, TAG, bak))
                    flush(lines)
                    return 6
            for rel in todo:
                rcopy(V2 + "\\" + rel + ".bak_" + TAG, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got == files[rel]["base"] else "НЕ СОШЛОСЬ"))
                if got != files[rel]["base"]:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ. Нужен старт стойки.")
            flush(lines)
            return 0
        plan = []
        for rel, f in files.items():
            lp = os.path.join(HERE, f["local"])
            if not os.path.exists(lp) or md5(lp) != f["new"]:
                log(lines, "СТОП: %s нет или md5 не %s (пересобери: --build)" % (lp, f["new"]))
                flush(lines)
                return 3
            cur = rmd5_or_locked(V2 + "\\" + rel) if not apply else rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == f["new"] else f["new"]))
            if cur == f["new"]:
                continue
            if cur == "locked":
                log(lines, "  заперт работающим процессом — база сверится при --apply (стойка остановлена)")
                plan.append((rel, lp, f["new"]))
                continue
            if cur != f["base"]:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю (снимок устарел: --build)" % (rel, cur, f["base"]))
                flush(lines)
                return 8
            plan.append((rel, lp, f["new"]))
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (%d файлов)" % len(plan))
            flush(lines)
            return 0
        for rel, lp, new in plan:
            DPB.backup_one(rel, TAG, lines)
            DPB.put(rel, lp, new, lines)
        log(lines, "ГОТОВО: P119 выложен (%d файлов). Старт стойки — за координатором; затем python deploy_p119.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


def main():
    """--build; иначе выкладка/откат/проверка по своему манифесту."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        build()
        return 0
    DPB.LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"
    return deploy()


if __name__ == "__main__":
    sys.exit(main())
