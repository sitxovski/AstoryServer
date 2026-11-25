# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# gen_charge_groups.py — ОДИН источник таблицы ключей P100_ChargeStack (заряды спецпредметов складываются при получении,
#   решение владельца 01.11.2026; проект Reports/item_dedup/charges/P100_PROJECT.md) для DLL и для SQL.
#   Вход: группы v2 «очевидных дублей» спецпредметов (Reports/item_dedup/_work/func_variants.json, ключ "v2") и ЖИВАЯ
#   GameServer/ItemTable_Info/Function_Table.txt (по SSH через srv_io; ток.0 код, ток.8 режим расхода, ток.9 заряды,
#   ток.24 привязка, ток.25 дни срока).
#   Правило складывания (группа целиком): у ВСЕХ кодов группы режим расхода 2 («−1 заряд») и срок 0; камни 401/363 исключены.
#   Ключ слияния = (номер группы + 1) * 10 + привязка — привязанное с непривязанным не смешивается.
#   [ИСПРАВЛЕНИЕ] заряды при выдаче = ток.9 целиком (оригинал хранит его в u8: 300 → 44 у 505/506/515).
#   Выход (папка p100_data рядом):
#     charge_groups.txt — для DLL (ConfigSet\charge_groups.txt): строка «# P100 ft_md5=<md5 FT> codes=<N> merge=<M> keys=<K>»,
#       затем по строке на КАЖДЫЙ код FT: «код<TAB>ключ(0 = не складывать)<TAB>заряды(ток.9)<TAB>режим<TAB>дни<TAB>привязка»;
#     charge_groups.json — сводка для аудита (группы, классы, числа);
#     charge_groups_client.csv — для клиента 5.1.4 (DataTable, [ИСПРАВЛЕНИЕ] ReservePackageSlots): «Name,Code,GroupKey,Charges»
#       на каждый код с ключом > 0 — тот же ключ и те же заряды, что у сервера (правило клиента = правило P100 один в один).
#   `--check` — только сверить, что выход на диске совпадает со свежей генерацией (для run_checks/сухого прогона).
# Без побочных эффектов при импорте.
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "p100_data")
VARIANTS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "Reports", "item_dedup", "_work", "func_variants.json"))
FT_REL = "GameServer/ItemTable_Info/Function_Table.txt"
EXCLUDE = {401, 363}          # камни разделения улучшения: у каждого свои Upcount/Opidx4 — не сливать


def parse_ft(raw):
    """Function_Table → {код: (режим, заряды, привязка, дни)}."""
    ft = {}
    for line in raw.decode("latin1").splitlines():
        t = line.split()
        if len(t) > 25 and t[0].isdigit():
            ft[int(t[0])] = (int(t[8]), int(t[9]), int(t[24]), int(t[25]))
    return ft


def build(ft_raw):
    """(текст charge_groups.txt, текст .sql, сводка) по байтам живой FT."""
    ft = parse_ft(ft_raw)
    groups = json.load(open(VARIANTS, encoding="utf-8"))["v2"]
    key, summary = {}, {"groups": [], "merge_groups": 0}
    for gi, codes in enumerate(groups):
        modes = {ft[c][0] for c in codes}
        days = {ft[c][3] for c in codes}
        ok = modes == {2} and days == {0} and not (set(codes) & EXCLUDE)
        cls = "merge" if ok else ("days" if days != {0} else "mode%s" % sorted(modes))
        summary["groups"].append({"group": gi, "codes": codes, "class": cls})
        if ok:
            summary["merge_groups"] += 1
            for c in codes:
                key[c] = (gi + 1) * 10 + ft[c][2]
    ft_md5 = hashlib.md5(ft_raw).hexdigest()
    lines = ["# P100 ft_md5=%s codes=%d merge=%d keys=%d" % (ft_md5, len(ft), len(key), len(set(key.values())))]
    for c in sorted(ft):
        m, ch, b, d = ft[c]
        lines.append("%d\t%d\t%d\t%d\t%d\t%d" % (c, key.get(c, 0), ch, m, d, b))
    txt = "\r\n".join(lines) + "\r\n"
    sql = ["-- P100_ChargeStack: ключи слияния зарядов (генератор gen_charge_groups.py, ft_md5=%s)" % ft_md5,
           "IF OBJECT_ID('dbo.AsdaChargeGroup') IS NULL",
           "  CREATE TABLE dbo.AsdaChargeGroup (Code INT NOT NULL PRIMARY KEY, GroupKey INT NOT NULL, Charges INT NOT NULL);",
           "DELETE FROM dbo.AsdaChargeGroup;"]
    for c in sorted(key):
        sql.append("INSERT dbo.AsdaChargeGroup (Code, GroupKey, Charges) VALUES (%d, %d, %d);" % (c, key[c], ft[c][1]))
    summary.update(ft_md5=ft_md5, ft_codes=len(ft), merge_codes=len(key), keys=len(set(key.values())),
                   charges_over_u8=sorted(c for c in ft if ft[c][1] > 255))
    csv_rows = ["Name,Code,GroupKey,Charges"] + ["%d,%d,%d,%d" % (c, c, key[c], ft[c][1]) for c in sorted(key)]
    summary["client_csv"] = "\r\n".join(csv_rows) + "\r\n"
    return txt, "\r\n".join(sql) + "\r\n", summary


def main():
    import srv_io
    sys.stdout.reconfigure(encoding="utf-8")
    txt, sql, summary = build(srv_io.read_live(FT_REL))
    client_csv = summary.pop("client_csv")
    files = {"charge_groups.txt": txt, "charge_groups.sql": sql, "charge_groups_client.csv": client_csv,
             "charge_groups.json": json.dumps(summary, ensure_ascii=False, indent=1) + "\n"}
    if "--check" in sys.argv:
        bad = [n for n, s in files.items()
               if not os.path.isfile(os.path.join(OUT, n)) or open(os.path.join(OUT, n), encoding="utf-8", newline="").read() != s]
        print("ОТКАЗ: расходится с живой FT: %s" % bad if bad else "совпадает с живой FT (ft_md5 %s)" % summary["ft_md5"])
        return 1 if bad else 0
    os.makedirs(OUT, exist_ok=True)
    for n, s in files.items():
        with open(os.path.join(OUT, n), "w", encoding="utf-8", newline="") as f:
            f.write(s)
    print("кодов FT %(ft_codes)d, складываемых %(merge_codes)d в %(merge_groups)d группах, ключей %(keys)d, "
          "заряды > 255: %(charges_over_u8)s, ft_md5 %(ft_md5)s" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
