# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_crabs_respawn.py — White Crab (type 590) respawn delay ×0.5 on Rein (04.11.2026, owner's decision for quest 403
#   "Tasting crabs": the step needs 15 drops of item 31091 from these crabs).
#
#   Record format (NpcServer decompile): Monster\<map>.svr = i16 count (in a 4-byte field) + count × 74-byte records.
#     +0 i32 slot index, +4 i16 x, +8 i16 y, +12 i32 RESPAWN DELAY in ms, +16 i32 monster type, +20 link leader,
#     +71 i16 group, +73 u8 alive at start.
#   +12 proof: the loader sub_4531B0 copies record +12 to monster +0x76C8; CAi::Frame_Monster (sub_461C80) respawns when
#     now − death tick ([cell+0x76F4]) ≥ [cell+0x76D0] (cell = monster − 8, 0x461F54…0x461FB5), the only scaling is a
#     player-load factor that only shortens it. No lower limit, no max-alive field (each record is one monster).
#   Read only at NpcServer start (sub_4531B0 has one caller, the init) → NpcServer restart needed to apply.
#   GameServer\MonsterData_Info\rein.svr is NOT changed: GameServer reads +4/+8/+16/+20/+48/+69/+73 only, never +12.
#
#   Changed: Rein.svr records 173…182 (type 590), +12: 15000 → 7500, in every NpcServer folder of stack_layout.
#   Usage: python deploy_crabs_respawn.py            — dry run (read only)
#          python deploy_crabs_respawn.py --apply    — backup + write (temp file + md5 check)
#          python deploy_crabs_respawn.py --rollback — restore from backup
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout
import deploy_p91 as base
from deploy_p90 import rmd5, rread, rcopy, rupload, rdel

V2 = base.V2
REL = r"Monster\Rein.svr"
BASE_MD5 = "36a450c4c880f1cd40813b6f5c38268a"       # live file 04.11.2026, same in all NpcServer folders
CRAB, OLD, NEW = 590, 15000, 7500
RECS = list(range(173, 183))
SRV_BACKUP = V2 + r"\_backup\2026-11-04_crabs"
LOCAL_BACKUP = r"@@ASTORY_DEV_ROOT@@\_backup\2026-11-04_crabs"


def patched(data):
    """Return (new bytes, [(record, x, y, old, new)]); raise if the records are not what we expect."""
    d = bytearray(data)
    n = struct.unpack_from("<h", d, 0)[0]
    assert len(d) == 4 + 74 * n, "size"
    found = [k for k in range(n) if struct.unpack_from("<i", d, 4 + 74 * k + 16)[0] == CRAB]
    assert found == RECS, "crab records %s, expected %s" % (found, RECS)
    out = []
    for k in RECS:
        o = 4 + 74 * k
        old = struct.unpack_from("<i", d, o + 12)[0]
        assert old == OLD, "record %d delay %d" % (k, old)
        struct.pack_into("<i", d, o + 12, NEW)
        out.append((k, struct.unpack_from("<h", d, o + 4)[0], struct.unpack_from("<h", d, o + 8)[0], old, NEW))
    return bytes(d), out


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply, rollback = "--apply" in sys.argv, "--rollback" in sys.argv
    print("== deploy_crabs_respawn %s" % ("APPLY" if apply else "ROLLBACK" if rollback else "dry run"))
    for ns in stack_layout.NPC_FOLDERS:
        p = V2 + "\\" + ns + "\\" + REL
        bak = SRV_BACKUP + "\\" + ns + "\\" + REL
        cur = rmd5(p)
        data = rread(p)
        assert hashlib.md5(data).hexdigest() == cur
        if rollback:
            bm = rmd5(bak)
            if bm != BASE_MD5:
                print("%s: STOP — backup %s is %s, not the base" % (ns, bak, bm))
                return 2
            if cur == BASE_MD5:
                print("%s: already base" % ns)
                continue
            rcopy(bak, p)
            print("%s: restored %s" % (ns, rmd5(p)))
            continue
        if cur != BASE_MD5:
            # Already patched = every crab delay is NEW and the rest equals the base (checked by md5 of the expected result).
            d = bytearray(data)
            for k in RECS:
                struct.pack_into("<i", d, 4 + 74 * k + 12, OLD)
            if hashlib.md5(bytes(d)).hexdigest() == BASE_MD5:
                print("%s: %s — already patched; skip" % (ns, cur))
                continue
            print("%s: %s — STOP, not the base and not our patch" % (ns, cur))
            return 3
        new, rows = patched(data)
        nm = hashlib.md5(new).hexdigest()
        print("%s: %s → %s" % (ns, cur, nm))
        for k, x, y, o, n in rows:
            print("   record %d at (%d,%d): delay %d → %d ms" % (k, x, y, o, n))
        if not apply:
            continue
        # backup: server and local
        loc = os.path.join(LOCAL_BACKUP, ns, REL)
        os.makedirs(os.path.dirname(loc), exist_ok=True)
        if not os.path.exists(loc):
            open(loc, "wb").write(data)
        assert hashlib.md5(open(loc, "rb").read()).hexdigest() == BASE_MD5
        if rmd5(bak) == "none":
            rcopy(p, bak)
        assert rmd5(bak) == BASE_MD5, "server backup md5"
        # write via temp file + md5
        tmp_local = loc + ".new"
        open(tmp_local, "wb").write(new)
        up = p + ".crabs_upload"
        rupload(tmp_local, up)
        if rmd5(up) != nm:
            rdel(up)
            raise SystemExit("%s: upload md5 mismatch — file untouched" % ns)
        rcopy(up, p)
        rdel(up)
        os.remove(tmp_local)
        got = rmd5(p)
        print("   written: %s %s" % (got, "OK" if got == nm else "MISMATCH"))
        if got != nm:
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
