# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_job4_rows.py — проверка staging ChangeJobAddSkillTable.txt (строки 6/17/28) ДО выкладки. 26.10.2026.
#   1. Формат и загрузчик: эмуляция загрузчика GameServer (GameServer.c:71655-71676, 0x4B2E63): fscanf %d; id 1…39, число > 0,
#      коды 500 ≤ c < числа записей SkillInfo.sif (1120) — иначе сервер прерывает загрузку (return 0).
#   2. staging = живая таблица (md5 8e0cd3a4) байт в байт + 3 строки в конце; GameServer = Indun_GameServer.
#   3. Выдача sub_48A8C0 (GameServer.c:55511): для каждого кода строк 6/17/28 — предшественники +200/+203/+206 = −1,
#      порог очков категории +190 = 0 (иначе навык молча не выдаётся); категория +189 = дерево 4-й профессии полосы;
#      маска классов +123 содержит подкласс и основной класс (для последующего изучения 5253).
#   4. P87_PickRow (AstoryServer/Docs/GameServer/job4-start-skills-p87.md §2): 1 ≤ S ≤ 39 и число строки S > 0 → строка S.
#   5. --stand: настоящий sub_481CE0 + живая AsdaPatch.dll на стенде stand_p87.exe (копии во временной папке, исходники AsdaPatch
#      не трогаются): с staging подклассы 6/17/28 → «row 6/17/28 n 5», со стоком → строка класса 3/14/25 (контраст).
# Запуск: python verify_job4_rows.py [--stand]   Код возврата 0 — всё [OK].
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "Patches", "AsdaPatch", "tools")))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2: Ch2_GameServer)
MIRROR = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Patches\AsdaPatch\tools\_srv_mirror\v2"
LIVE = MIRROR + r"\GameServer\SkillTable_Info\ChangeJobAddSkillTable.txt"
STOCK = r"@@ASTORY_DEV_ROOT@@\Donors\GameServer_stock\SkillTable_Info\ChangeJobAddSkillTable.txt"
SIF = MIRROR + r"\GameServer\SkillTable_Info\SkillInfo.sif"
STAND = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Patches\AsdaPatch\tools\stand_p87\stand_p87.exe"
DLL = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Patches\AsdaPatch\out\AsdaPatch.dll"
EXE = MIRROR + r"\GameServer\GameServer.exe"
LIVE_MD5 = "8e0cd3a44563ab0162505b6a924fc848"
NEW = {6: (3, 10, [617, 619, 632, 633, 634]), 17: (14, 11, [826, 828, 841, 842, 843]), 28: (25, 12, [1050, 1051, 1062, 1065, 1066])}
ok_n = bad_n = 0


def ok(cond, text):
    global ok_n, bad_n
    print(("  [OK] " if cond else "  [!!] ") + text)
    if cond:
        ok_n += 1
    else:
        bad_n += 1


def load(path, nrec):
    """Эмуляция загрузчика: (строки {id: [коды]}, ошибка или None)."""
    toks = open(path, "rb").read().split()
    rows, i = {}, 0
    while i < len(toks):
        rid = int(toks[i]); n = int(toks[i + 1]); i += 2
        if rid <= 0 or rid > 39 or n <= 0:
            return rows, "строка id %d число %d — загрузчик вернёт 0" % (rid, n)
        codes = [int(t) for t in toks[i:i + n]]; i += n
        if len(codes) != n or any(c < 500 or c >= nrec for c in codes):
            return rows, "строка %d: коды %s вне 500…%d" % (rid, codes, nrec - 1)
        rows[rid] = codes
    return rows, None


def main():
    sif = open(SIF, "rb").read()
    nrec = len(sif) // 209
    S = {struct.unpack_from("<h", sif, 209 * i)[0]: sif[209 * i:209 * i + 209] for i in range(nrec)}
    live = open(LIVE, "rb").read()
    print("== verify_job4_rows")
    ok(hashlib.md5(live).hexdigest() == LIVE_MD5, "зеркало живой таблицы md5 %s (ждём %s)" % (hashlib.md5(live).hexdigest(), LIVE_MD5))
    files = [os.path.join(HERE, f, "SkillTable_Info", "ChangeJobAddSkillTable.txt") for f in stack_layout.GS_FOLDERS]
    data = [open(p, "rb").read() for p in files]
    ok(len(set(data)) == 1, "staging всех GameServer (%s) одинаковый (md5 %s)" % (", ".join(stack_layout.GS_FOLDERS), hashlib.md5(data[0]).hexdigest()))
    ok(data[0].startswith(live), "прежние 12 строк — байт в байт как на живом")
    tail = data[0][len(live):].split(b"\r\n")
    ok(len(tail) == 4 and tail[-1] == b"" and all(len(l.split(b"\t")) == 36 for l in tail[:-1]), "3 новые строки: 36 полей TAB, CRLF")
    rows, err = load(files[0], nrec)
    ok(err is None and len(rows) == 15, "загрузчик: %s, строк %d (ждём 15)" % (err or "ошибок нет", len(rows)))
    old, _ = load(LIVE, nrec)
    ok(all(rows.get(k) == v for k, v in old.items()), "строки живой таблицы не изменились")
    for sj, (job, tree, codes) in NEW.items():
        ok(rows.get(sj) == codes, "строка %d = %s" % (sj, " ".join(map(str, codes))))
        good = True
        for c in codes:
            r = S[c]
            pre = [struct.unpack_from("<h", r, o)[0] for o in (200, 203, 206)]
            mask = struct.unpack_from("<Q", r, 123)[0]
            good &= r[189] == tree and r[190] == 0 and pre == [-1, -1, -1] and (mask >> sj) & 1 == 1 and (mask >> job) & 1 == 1
        ok(good, "подкласс %d: все коды — категория %d, порог 0, без предшественников, маска классов с %d и %d (sub_48A8C0 выдаст все 5)" % (sj, tree, sj, job))
        n = len(rows.get(sj, []))
        ok(1 <= sj <= 39 and n > 0, "P87_PickRow: подкласс %d → строка %d (%d навыков), не сток" % (sj, sj, n))
    if "--stand" in sys.argv:
        stand()
    print("== ИТОГ verify_job4_rows: ok=%d bad=%d ==" % (ok_n, bad_n))
    return 0 if bad_n == 0 else 1


def stand():
    """Стенд stand_p87 во временной папке: staging и сток, разбор журнала P87."""
    dll_md5 = hashlib.md5(open(DLL, "rb").read()).hexdigest()
    print("  стенд: stand_p87.exe + AsdaPatch.dll %s + GameServer.exe %s" % (dll_md5[:8], hashlib.md5(open(EXE, "rb").read()).hexdigest()[:8]))
    pat = re.compile(rb"P87 sub (\d+) job (\d+) row (\d+) n (\d+) a3 1 title")
    for name, table, want in (("staging", os.path.join(HERE, "GameServer", "SkillTable_Info", "ChangeJobAddSkillTable.txt"), {6: (6, 5), 17: (17, 5), 28: (28, 5)}),
                              ("сток", STOCK, {6: (3, 0), 17: (14, 0), 28: (25, 0)})):
        d = tempfile.mkdtemp(prefix="job4rows_")
        try:
            for src in (STAND, DLL, EXE):
                shutil.copy2(src, d)
            p = subprocess.run([os.path.join(d, "stand_p87.exe"), os.path.join(d, "GameServer.exe"), os.path.join(d, "AsdaPatch.dll"), "on", table],
                               cwd=d, capture_output=True, timeout=600)
            seen = {}
            for root, _, fs in os.walk(os.path.join(d, "Log")):
                for f in fs:
                    for m in pat.finditer(open(os.path.join(root, f), "rb").read()):
                        seen[int(m.group(1))] = (int(m.group(3)), int(m.group(4)))
            for sj, w in want.items():
                ok(seen.get(sj) == w, "стенд (%s): подкласс %d → строка %s, навыков %s (ждём %d / %d)" % (name, sj, *(seen.get(sj) or ("—", "—")), *w))
            for sj in (4, 15, 26):
                ok(seen.get(sj) == (sj, 5), "стенд (%s): подкласс %d → строка %s (ждём %d, 5 навыков)" % (name, sj, seen.get(sj), sj))
            if name == "сток":
                ok(b"bad=0" in p.stdout, "стенд (сток): собственный итог stand_p87 bad=0")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
