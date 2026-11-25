# Copyright (c) 2026 @sitxovski (Discord)
# Точечный откат клеток двух досок в 4 серверных копиях .npc + манифесты (22.10.2026).
import hashlib, json, os, shutil, struct, sys
DRY = "--apply" not in sys.argv
# ★ 26.10.2026: стойка — ТОЛЬКО по SSH (srv_io: чтение через кэш srv_mirror, запись с бэкапами и сверкой md5);
#   шара \\@@ASTORY_SERVER_HOSTNAME@@ запрещена (22.10). Запись — при остановленных GameServer/NpcServer (файл занят → отказ).
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "AsdaPatch", "tools")))
import stack_layout   # noqa: E402  ★ 26.10.2026: единый состав стойки (канал 2)
import srv_io   # noqa: E402
SUBS = [d + "/NpcData_Info" for d in stack_layout.GS_FOLDERS] + [d + "/NpcInfo" for d in stack_layout.NPC_FOLDERS]   # 26.10: + Ch2_*
# файл, запись, NpcId, клетка стока, (манифест, gy по DA_WalkGrid)
FIX = [("Sillaris.npc", 36, 9, (400, 396), "silalis", 750.0), ("Rein.npc", 14, 148, (46, 389), "rein", 816.0)]
BK = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-22_npc_boards_stock"
SRV_BK = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\2026-10-22_npc_boards\orig"   # бэкап на сервере (srv_io: <SRV_BK>\<путь от v2>)
PATCH = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/NpcData/2026-10-22_npc_boards"
md5 = lambda b: hashlib.md5(b).hexdigest()

def backup(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
    assert os.path.getsize(dst) == os.path.getsize(src) and md5(open(dst, "rb").read()) == md5(open(src, "rb").read()), dst

for fname, rec, nid, (tx, tz), mp, gy in FIX:
    news = set()
    for sub in SUBS:
        rel = sub + "/" + fname
        live = srv_io.read_live(rel)   # по SSH
        b = bytearray(live)
        o = rec * 0xDD
        assert struct.unpack_from("<I", b, o + 4)[0] == nid, (p, rec)
        old = struct.unpack_from("<hhh", b, o + 8)
        struct.pack_into("<hh", b, o + 8, tx, tz)
        print("%s %s: rec %d id %d клетка %s -> (%d,%d), face %d; md5 %s -> %s" % (sub, fname, rec, nid, old[:2], tx, tz, old[2],
              md5(live)[:8], md5(b)[:8]))
        news.add(md5(b))
        if not DRY:
            if sub == SUBS[0]:
                os.makedirs(PATCH + "/orig", exist_ok=True)
                if not os.path.exists(PATCH + "/orig/" + fname):
                    open(PATCH + "/orig/" + fname, "wb").write(live)
                os.makedirs(PATCH + "/new", exist_ok=True)
                open(PATCH + "/new/" + fname, "wb").write(b)
            # бэкап рядом (.bak_20261022_npc_boards), на сервере (SRV_BK) и локально (BK/@@ASTORY_SERVER_HOSTNAME@@/v2/…), запись и сверка md5 — srv_io
            srv_io.put_live(rel, bytes(b), ".bak_20261022_npc_boards", SRV_BK, BK + "/@@ASTORY_SERVER_HOSTNAME@@/v2")
    assert len(news) == 1, "копии разошлись: %s" % news
    # манифест
    mf = "@@ASTORY_DEV_ROOT_FWD@@/Data/Export/maps/%s/npc_manifest.json" % mp
    d = json.load(open(mf, encoding="utf-8"))
    n = [n for n in d["npc"] if n.get("idx") == rec and n.get("type") == nid]
    assert len(n) == 1, mf
    n = n[0]
    print("  манифест %s: было %s" % (mp, {k: n.get(k) for k in ("gx", "gy", "gz", "tileX", "tileZ", "face")}))
    n.update({"gx": tx * 100 + 50.0, "gy": gy, "gz": tz * 100 + 50.0, "tileX": tx, "tileZ": tz})
    n.pop("owner_edit_2026_10_18", None)
    n["restored_stock_2026_10_22"] = "ручной крен 18.10 снят: модель стоит сама после исправления идл-клипа (служебная кость); клетка и поворот — сток"
    if not DRY:
        backup(mf, BK + "/Data/Export/maps/%s/npc_manifest.json" % mp)
        json.dump(d, open(mf, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("СУХОЙ ПРОГОН" if DRY else "ЗАПИСАНО")
