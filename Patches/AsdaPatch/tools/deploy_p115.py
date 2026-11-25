# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p115.py — P115: ОПЦИЯ ЗАТОЧКИ +6 У ХВОСТОВОГО СНАРЯЖЕНИЯ (08.11.2026, пачка 17, баг 8 «Ruby Celestine: Fort не даёт третий стат»;
#   сессия set-fort). Разбор и ведомость — Reports/batch17/set_fort/ (REPORT.md, fort_option_audit.csv, fort_option_proposal.csv).
#   ПРИЧИНА. `CharShellItemUpgrade_0 @0x4FEE50` на ступени 6 кладёт опцию в запись +41/+43 из группы SowelCombine +154 (col49, токен 48);
#   `Recv_User_UpperRefine` берёт +156 (col50, токен 49). У 513 вещей «хвоста» (код > 76314) эти группы = −1 — их оставил
#   `server_sowel_tail_restore.py` (30.10, класс C), подняв предел до 5+грейд. Итог: +6 достижима, опции нет
#   (живой журнал CRTJIN_20261101: «Recv_User_ShellItemUpgrade(10) ItemCode=79216 AddIndex=-1»).
#   ПРАВКА: токены 48/49 := col49_new/col50_new для 504 кодов с уверенностью «высокая» (правила стока: костюмы — БАЗА+5·вариант+слот,
#   оружие — блок по виду). 79420 («низкая») и 8 вещей Gloomy (нет данных), 150 стоковых — НЕ входят (решение владельца 08.11).
#   Только новые заточки: уже заточенные до +6…+8 вещи опцию не получат (сервер бросает её на переходе к ступени 6), БД не трогается.
#   Таблица читается при старте GameServer — нужен рестарт. Клиент не меняется (alpha-6.9.9 показывает пару +41 уже сейчас).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_p115.py
#   python deploy_p115.py --build      — снимок SowelCombine всех GameServer по SSH (только чтение) → p115_data/srv_in, правка → srv_out,
#                                        манифест md5, построчный diff (p115_data/diff_<папка>.tsv); сверка «изменены ровно 504×2 ячейки»
#   python deploy_p115.py              — сухой прогон (md5 базы на стойке = манифесту; ничего не пишет)
#   --apply (GameServer ОСТАНОВЛЕНЫ) / --rollback / --check-started — общий путь deploy_premium_boxes.py (бэкап .bak_<tag> на стойке
#     и локально в _backup, замена, сверка md5; откат — из .bak_<tag>).
# Модуль без побочных эффектов при импорте.
import csv
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки (все GameServer)
import deploy_premium_boxes as DPB                    # бэкап/заливка/откат/проверка старта (без побочных эффектов)

DATA = os.path.join(HERE, "p115_data")                # снимок, выход, манифест, diff этой правки
TAG = "20261108_p115"                                 # суффикс бэкапов стойки .bak_<tag>
PROPOSAL = r"@@ASTORY_DEV_ROOT@@\Reports\batch17\set_fort\fort_option_proposal.csv"   # ведомость (code, col49_new, col50_new, confidence)
SC_REL = "ItemTable_Info\\SowelCombine.txt"           # заточка и совел
TOK_O49, TOK_O50 = 48, 49                             # 0-базные токены: +154 (опция ступени 6), +156 (высшая переработка)
EXPECT_CODES = 504                                    # охват по решению владельца
EXPECT_BASE_MD5 = "6eded51b6400bf03a268719e4eab46f8"  # живой SowelCombine на 08.11 (все три GameServer)
SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"        # ключ SSH
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"             # стойка
SRV_ROOT = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"                  # корень стойки


def md5(path):
    """md5 файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def scp_get(rel, dst):
    """Снимок файла стойки (только чтение) → dst; возврат md5."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    src = "%s:%s/%s" % (SSH_HOST, SRV_ROOT, rel.replace("\\", "/"))
    p = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", src, dst], capture_output=True, timeout=600)
    if p.returncode != 0:
        raise SystemExit("ОТКАЗ: scp %s: %s" % (rel, p.stderr.decode("utf-8", "replace")[-200:]))
    return md5(dst)


def load_targets():
    """code → (col49, col50) из ведомости: только хвост и уверенность «высокая»."""
    out = {}
    with open(PROPOSAL, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f, delimiter=";"):
            if r["origin"] == "хвост" and r["confidence"] == "высокая":
                out[r["code"]] = (int(r["col49_now"]), int(r["col50_now"]), int(r["col49_new"]), int(r["col50_new"]))
    if len(out) != EXPECT_CODES:
        raise SystemExit("ОТКАЗ: в ведомости %d кодов, ждали %d" % (len(out), EXPECT_CODES))
    return out


def patch_file(src, dst, targets, diff_path):
    """Правка токенов 48/49 строк целей, разделители байт в байт. Сверка: ровно len(targets) строк и 2·len ячеек."""
    data = open(src, "rb").read()
    lines = data.split(b"\r\n")
    left = dict(targets)
    rows = []
    for i in range(1, len(lines)):
        parts = re.split(rb"(\s+)", lines[i])          # чётные — токены, нечётные — разделители
        if not parts or parts[0] == b"":
            continue
        code = parts[0].decode("latin1")
        t = left.pop(code, None)
        if t is None:
            continue
        old49, old50, new49, new50 = t
        if int(parts[2 * TOK_O49]) != old49 or int(parts[2 * TOK_O50]) != old50:
            raise SystemExit("ОТКАЗ: код %s — на стойке %s/%s, ведомость ждёт %d/%d" % (
                code, parts[2 * TOK_O49].decode(), parts[2 * TOK_O50].decode(), old49, old50))
        parts[2 * TOK_O49] = str(new49).encode()
        parts[2 * TOK_O50] = str(new50).encode()
        new = b"".join(parts)
        if len(new.split()) != len(lines[i].split()):
            raise SystemExit("ОТКАЗ: код %s — изменилось число токенов" % code)
        rows.append((i, code, old49, new49, old50, new50))
        lines[i] = new
    if left:
        raise SystemExit("ОТКАЗ: %s — нет строк кодов %s" % (src, sorted(left)[:5]))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(b"\r\n".join(lines))
    # Независимая сверка: построчно и по токенам.
    a, o = data.split(b"\r\n"), open(dst, "rb").read().split(b"\r\n")
    if len(a) != len(o):
        raise SystemExit("ОТКАЗ: %s — изменилось число строк" % dst)
    cells = lines_changed = 0
    for x, y in zip(a, o):
        if x == y:
            continue
        lines_changed += 1
        tx, ty = re.split(rb"(\s+)", x), re.split(rb"(\s+)", y)
        bad = [k for k in range(len(tx)) if tx[k] != ty[k] and k not in (2 * TOK_O49, 2 * TOK_O50)]
        if bad or len(tx) != len(ty):
            raise SystemExit("ОТКАЗ: %s — изменено не только 48/49 (позиции %s)" % (dst, bad[:5]))
        cells += sum(1 for k in (2 * TOK_O49, 2 * TOK_O50) if tx[k] != ty[k])
    if lines_changed != len(targets) or cells != 2 * len(targets):
        raise SystemExit("ОТКАЗ: %s — строк %d, ячеек %d; ждали %d и %d" % (dst, lines_changed, cells, len(targets), 2 * len(targets)))
    with open(diff_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("line\tcode\tcol49_old\tcol49_new\tcol50_old\tcol50_new\n")
        for r in rows:
            f.write("%d\t%s\t%d\t%d\t%d\t%d\n" % r)
    return lines_changed, cells


def build():
    """Снимки SowelCombine всех GameServer, точечная правка, манифест md5, diff."""
    targets = load_targets()
    print("кодов к правке: %d" % len(targets))
    files, outs = {}, set()
    for d in stack_layout.GS_FOLDERS:
        full = d + "\\" + SC_REL
        loc_in = os.path.join(DATA, "srv_in", d, "SowelCombine.txt")
        base = scp_get(full, loc_in)
        if base != EXPECT_BASE_MD5:
            raise SystemExit("ОТКАЗ: %s md5 %s ≠ ожидаемого %s — таблицу кто-то менял, пересобрать ведомость" % (full, base, EXPECT_BASE_MD5))
        loc_out = os.path.join(DATA, "srv_out", d, "SowelCombine.txt")
        n, cells = patch_file(loc_in, loc_out, targets, os.path.join(DATA, "diff_%s.tsv" % d))
        new = md5(loc_out)
        outs.add(new)
        print("%-48s %s → %s  строк %d, ячеек %d" % (full, base, new, n, cells))
        files[full] = {"local": os.path.relpath(loc_out, HERE).replace("\\", "/"), "base": base, "new": new}
    if len(outs) != 1:
        raise SystemExit("ОТКАЗ: выход разный на GameServer: %s" % sorted(outs))
    man = {"tag": TAG, "patch": "P115", "codes": len(targets), "files": files}
    with open(os.path.join(DATA, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    print("манифест: %s (файлов %d)" % (os.path.join(DATA, "manifest.json"), len(files)))


def main():
    """--build; иначе общий путь deploy_premium_boxes по своему манифесту."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        build()
        return 0
    DPB.MANIFEST = os.path.join(DATA, "manifest.json")
    DPB.LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"
    return DPB.main()


if __name__ == "__main__":
    sys.exit(main())
