# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# build_pet31.py — строка 31 «SnowLion» в PetData_Info\PetInfo_Table.txt трёх GameServer (29.10.2026, наш дефект: яйцо 76338
#   «Snow Lion Egg» ведёт на питомца 31, а на сервере строки 0–30 → Recv_IncubatorReq отвечает 6103 с кодом 8 и яйцо не
#   вылупляется; разбор — Reports/donor_wod/_research/sys_petfish.md §1.2, отчёт — Reports/pet31_snowlion/REPORT.md).
#
#   клиентская pettable (RawAssets/Data/ItemDB/pettable.csv, запись 31 = `pettable.bin`) по проверенному соответствию полей
#   «клиент → сервер» (см. CLIENT_TO_SRV; на строках 0–30 совпадает 29 из 31 строки целиком, у 13/14 расходится только ток.3 —
#   KNOWN_TOK3); имя — английская запись оригинала `L10N/en/DT_Loc_pettable_en.csv` «31.Name = SnowLion» (источник ORIG).
#   Ток.15 (+52) — маска видов корма (`FeedTypeMask`: кормление 6109 отказывает кодом 5, если `(mask & (1 << вид корма)) == 0`,
#   :35579) = биты трёх клиентских полей `OptRarityCode0..2` (имя колонки в CSV — миснейм: это три допустимых вида корма).
#
# Команды:
#   python build_pet31.py fetch    — снимок PetData_Info + item_table/SowelCombine трёх GS по SSH (srv_io, только чтение) → data_pet31/srv_in
#   python build_pet31.py build    — srv_out (+строка 31, счётчик 31 → 32) + manifest.json + стенд
#   python build_pet31.py verify   — стенд по srv_out (загрузчик, прежние строки байт в байт, гейт яйца 76338)
# Выкладка — deploy_pet31.py (через restart_stack.py). Без побочных эффектов при импорте.
import csv
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data_pet31")
SRV_IN = os.path.join(DATA, "srv_in")                     # снимок стойки до правки
SRV_OUT = os.path.join(DATA, "srv_out")                   # файлы к выкладке
MANIFEST = os.path.join(DATA, "manifest.json")
TAG = "20261029_pet31"
PET_REL = "PetData_Info\\PetInfo_Table.txt"
AUX = ("ItemTable_Info\\item_table.txt", "ItemTable_Info\\SowelCombine.txt", "PetData_Info\\PetIncubateRate_Table.txt")
CLIENT_CSV = r"@@ASTORY_DEV_ROOT@@\AstoryClient\RawAssets\Data\ItemDB\pettable.csv"
CLIENT_EN = r"@@ASTORY_DEV_ROOT@@\AstoryClient\RawAssets\Text\L10N\en\DT_Loc_pettable_en.csv"
PET_ID = 31
EGG = 76338                                               # «Snow Lion Egg»: item_table ток.9 = 31, ток.17 = 109
ITEM_FIRST = 20551                                        # первый код item_table (sub_532A90)
KNOWN_TOK3 = {13: ("0", "2"), 14: ("0", "2")}             # Tiga, Bunny: ток.3 (+19) клиент 0 / сервер 2 — так в стоке
# Колонки pettable.csv, которые дают токены 2…14 и 16 серверной строки (ток.15 — маска редкостей, ток.0/1 — id/имя).
CLIENT_TO_SRV = ("Grade", "Unk72", "Category", "DurabilityFactor", "FeedCostFactor", "GoldRewardFactor", "ExpRewardFactor",
                 "OptionId0", "OptionValue0", "OptionId1", "OptionValue1")


def out(*a):
    print(*a, flush=True)


def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()


def gs_dirs():
    sys.path.insert(0, HERE)
    import stack_layout                                   # единый состав стойки (GameServer, Indun_GameServer, Ch2_GameServer)
    return list(stack_layout.GS_FOLDERS)


def toks(line):
    return line.split()                                   # fscanf "%s": пробелы и табуляции — разделители


def client_rows():
    """Клиентская pettable: id → (поля CSV, opt2 id/val и три вида корма из DataHex — у CSV opt2 нет)."""
    rows = {}
    for r in csv.DictReader(open(CLIENT_CSV, encoding="utf-8-sig")):
        h = bytes.fromhex(r["DataHex"])
        u = struct.pack("<i", int(r["Unk144"]))
        p = h.find(u, 60)                                 # Unk144 сразу за opt2 id/val и тремя видами корма
        o2id, o2v, r0, r1, r2 = struct.unpack("<5i", h[p - 20:p])
        rows[int(r["Id"])] = (r, o2id, o2v, (r0, r1, r2))
    return rows


def client_to_srv(rec, name):
    """17 токенов серверной строки из клиентской записи (порядок загрузчика :69639-69680)."""
    r, o2id, o2v, rar = rec
    mask = sum(1 << x for x in rar if x >= 0)
    return [r["Id"], name] + [r[k] for k in CLIENT_TO_SRV] + [str(o2id), str(o2v), str(mask), r["Unk144"]]


def en_name(pid):
    for r in csv.DictReader(open(CLIENT_EN, encoding="utf-8-sig")):
        if r["Name"] == "%d.Name" % pid:
            return r["Text"]
    raise SystemExit("нет EN-имени породы %d в %s" % (pid, CLIENT_EN))


def cmd_fetch():
    sys.path.insert(0, HERE)
    import srv_io
    for d in gs_dirs():
        for rel in (PET_REL,) + AUX:
            data = srv_io.read_live("%s/%s" % (d, rel.replace("\\", "/")))
            p = os.path.join(SRV_IN, d, *rel.split("\\"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
            out("снимок %-18s %-40s %8d б %s" % (d, rel, len(data), hashlib.md5(data).hexdigest()))
    return 0


def new_line():
    """Строка 31 из клиентской записи + EN-имя; кодировка ASCII, CRLF — как у стока."""
    name = en_name(PET_ID)
    t = client_to_srv(client_rows()[PET_ID], name)
    return ("\t".join(t) + "\r\n").encode("ascii")


def cmd_build():
    man = {"tag": TAG, "files": {}}
    line = new_line()
    for d in gs_dirs():
        src = open(os.path.join(SRV_IN, d, *PET_REL.split("\\")), "rb").read()
        head, body = src.split(b"\r\n", 1)
        cnt = int(head)
        if cnt != PET_ID:
            raise SystemExit("%s: счётчик %d, ожидался %d (строка 31 уже есть или таблица другая) — стоп" % (d, cnt, PET_ID))
        if not body.endswith(b"\r\n"):
            raise SystemExit("%s: файл не кончается CRLF — разберись" % d)
        new = str(cnt + 1).encode("ascii") + b"\r\n" + body + line
        p = os.path.join(SRV_OUT, d, *PET_REL.split("\\"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(new)
        rel = d + "\\" + PET_REL
        man["files"][rel] = {"local": os.path.relpath(p, HERE).replace("\\", "/"),
                             "base": hashlib.md5(src).hexdigest(), "new": hashlib.md5(new).hexdigest()}
        out("%-18s %d → %d строк, %d → %d б, %s → %s" % (d, cnt, cnt + 1, len(src), len(new),
                                                         man["files"][rel]["base"][:8], man["files"][rel]["new"][:8]))
    json.dump(man, open(MANIFEST, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    out("строка 31: " + line.decode("ascii").replace("\t", " ").strip())
    return 0 if cmd_verify() else 1


def load_pet(path):
    """Поток токенов загрузчика: счётчик, затем по 17 на запись; имя — memcpy 16 из нулевого буфера."""
    t = open(path, "rb").read().split()
    n = int(t[0])
    recs = [t[1 + 17 * i:1 + 17 * (i + 1)] for i in range(n)]
    return n, recs, len(t) - 1 - 17 * n


def cmd_verify():
    errs = []
    cl = client_rows()
    for d in gs_dirs():
        p = os.path.join(SRV_OUT, d, *PET_REL.split("\\"))
        n, recs, extra = load_pet(p)
        if extra:
            errs.append("%s: лишних токенов %d после %d записей" % (d, extra, n))
        if n != PET_ID + 1 or any(len(r) != 17 for r in recs):
            errs.append("%s: счётчик %d / неполные записи" % (d, n))
        for i, r in enumerate(recs):
            if int(r[0]) != i:
                errs.append("%s: запись %d с id %s" % (d, i, r[0]))
            if len(r[1]) > 15:
                errs.append("%s: имя %r длиннее 15 б (memcpy 16 без нуля)" % (d, r[1]))
        a = open(os.path.join(SRV_IN, d, *PET_REL.split("\\")), "rb").read().split(b"\r\n", 1)[1]
        o = open(p, "rb").read().split(b"\r\n", 1)[1]
        if not o.startswith(a):
            errs.append("%s: прежние строки 0–30 изменены" % d)
        # клиент → сервер по всем 32 породам (строка 31 — по тому же правилу, имя — EN оригинала)
        for i, r in enumerate(recs):
            want = client_to_srv(cl[i], r[1].decode("latin-1"))
            got = [x.decode("latin-1") for x in r]
            diff = [k for k in range(17) if want[k] != got[k]]
            if diff and not (diff == [3] and KNOWN_TOK3.get(i) == (want[3], got[3])):
                errs.append("%s: порода %d ≠ клиенту в токенах %s" % (d, i, diff))
        # гейт Recv_IncubatorReq для всех яиц (подтип 109, ток.17): 0 ≤ ток.9 < счётчик (:34623); шанс — SowelCombine ток.45 (:34620)
        it = [toks(ln) for ln in open(os.path.join(SRV_IN, d, "ItemTable_Info", "item_table.txt"), "rb").read().split(b"\r\n")[1:]
              if ln.strip()]
        sc = {int(t[0]): t for t in (toks(ln) for ln in open(os.path.join(SRV_IN, d, "ItemTable_Info", "SowelCombine.txt"),
                                                              "rb").read().split(b"\r\n")[1:] if ln.strip())}
        rate = [toks(ln) for ln in open(os.path.join(SRV_IN, d, "PetData_Info", "PetIncubateRate_Table.txt"), "rb")
                .read().split(b"\r\n")[1:] if ln.strip()]
        eggs = [(int(t[0]), int(t[9])) for t in it if t[17] == b"109"]
        bad = [(c, pt) for c, pt in eggs if not 0 <= pt < n]
        if bad:
            errs.append("%s: яйца без строки PetInfo: %s" % (d, bad))
        egg = [pt for c, pt in eggs if c == EGG]
        ri = int(sc[EGG][45]) if EGG in sc else -1
        chance = int(rate[ri][1]) if 0 <= ri <= 9 and ri < len(rate) else 0
        out("стенд %-18s пород %d, яиц %d (вне таблицы %d); %d → порода %s «%s», шанс без катализатора %d/100000"
            % (d, n, len(eggs), len(bad), EGG, egg, recs[egg[0]][1].decode() if egg and egg[0] < n else "—", chance))
        if not egg or egg[0] != PET_ID:
            errs.append("%s: яйцо %d → %s, ожидалась порода %d" % (d, EGG, egg, PET_ID))
    if len({md5(os.path.join(SRV_OUT, d, *PET_REL.split("\\"))) for d in gs_dirs()}) != 1:
        errs.append("srv_out трёх GS различается")
    out("стенд: ошибок %d" % len(errs))
    for e in errs:
        out("  ! " + e)
    return not errs


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "fetch":
        return cmd_fetch()
    if cmd == "build":
        return cmd_build()
    if cmd == "verify":
        return 0 if cmd_verify() else 1
    out(__doc__ or "build_pet31.py fetch | build | verify")
    return 2


if __name__ == "__main__":
    sys.exit(main())
