# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_item_dedup.py — выкладка серверных таблиц дедупликации предметов (решение владельца 01.11.2026, отчёт
#   Reports/item_dedup/) для restart_stack.py: `--apply` пишет файлы, собранные Reports/item_dedup/_work/dd_apply_server.py
#   (папка stage2/srv_out, манифест stage2/srv_md5.tsv: файл, md5 живого на момент сборки, md5 нового), во все папки стойки,
#   перечисленные в манифесте (GameServer/NpcServer + Indun_* + Ch2_* по stack_layout.py), через srv_io.put_live
#   (бэкапы: рядом <файл>.bak_itemdedup_20261101, в v2\_backup\itemdedup_20261101 и локально RE/dumps/server_item_dedup/live_backup;
#   md5 сверяется после записи). При успехе печатает «ГОТОВО».
#   Без `--apply` — сухой прогон: сверка живых md5 с манифестом и локальных новых файлов; ничего не пишет.
#   `--rollback` — вернуть живые файлы из локальных бэкапов (только если живой = новый из манифеста).
# Отказ без записи, если хоть один живой файл не совпал с манифестом (таблицу успели поменять — пересобрать dd_apply_server.py).
# Без побочных эффектов при импорте.
import csv
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
STAGE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "Reports", "item_dedup", "stage2"))
MANIFEST = os.path.join(STAGE, "srv_md5.tsv")
NEWDIR = os.path.join(STAGE, "srv_out")
# ★ волна выкладки (у каждой свои бэкапы, иначе откат волны вернул бы стойку к состоянию до ПЕРВОЙ волны):
#   20261101   — этап 2 (выложен координатором 01.11; бэкапы *.bak_itemdedup_20261101, v2\_backup\itemdedup_20261101,
#                локально live_backup; манифест stage2/srv_md5_deployed_v1.tsv);
#   20261101b  — функционалки F1 + основной спецпредмет = продаваемый в витрине + строки шлюза gp7 (текущая).
WAVE = "20261101b"
LOCAL_BACKUP = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "RE", "dumps", "server_item_dedup", "live_backup_" + WAVE))
SUFFIX = ".bak_itemdedup_" + WAVE
SRV_BACKUP = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\itemdedup_" + WAVE


def manifest():
    """Строки манифеста: (относительный путь от v2, md5 живого, md5 нового)."""
    with open(MANIFEST, encoding="utf-8", newline="") as f:
        return [(r["file"], r["md5_live"], r["md5_new"]) for r in csv.DictReader(f, delimiter="\t")]


def local_new(rel):
    """Байты нового файла из srv_out."""
    with open(os.path.join(NEWDIR, *rel.replace("/", "\\").split("\\")), "rb") as f:
        return f.read()


def main():
    import srv_io   # SSH-доступ к стойке (чтение md5 / запись с бэкапами)
    rows = manifest()
    print("файлов в манифесте: %d" % len(rows))
    bad = 0
    for rel, live_want, new_want in rows:
        data = local_new(rel)
        if hashlib.md5(data).hexdigest() != new_want:
            print("  ОТКАЗ: локальный новый %s не сходится с манифестом" % rel); bad += 1; continue
        cur = srv_io.live_md5(rel)
        state = "живой = снимок" if cur == live_want else ("уже новый" if cur == new_want else "ЖИВОЙ ИЗМЕНИЛСЯ (%s)" % cur)
        if cur not in (live_want, new_want):
            bad += 1
        print("  %-62s %s -> %s  [%s]" % (rel, live_want[:8], new_want[:8], state))
    if bad:
        print("ОТКАЗ: %d расхождений — ничего не записано" % bad)
        return 1
    if "--rollback" in sys.argv:
        for rel, live_want, new_want in rows:
            if srv_io.live_md5(rel) != new_want:
                print("  пропуск отката %s: живой не равен новому" % rel); continue
            p = os.path.join(LOCAL_BACKUP, *rel.replace("/", "\\").split("\\"))
            with open(p, "rb") as f:
                old = f.read()
            if hashlib.md5(old).hexdigest() != live_want:
                print("ОТКАЗ отката: локальный бэкап %s не сходится" % rel); return 1
            srv_io.put_live(rel, old, ".bak_itemdedup_rollback", SRV_BACKUP + "_rollback", LOCAL_BACKUP + "_rollback")
        print("ГОТОВО: откат выполнен")
        return 0
    if "--apply" not in sys.argv:
        print("сухой прогон: запись — с --apply (через restart_stack.py --deploy deploy_item_dedup.py)")
        return 0
    for rel, live_want, new_want in rows:
        got = srv_io.put_live(rel, local_new(rel), SUFFIX, SRV_BACKUP, LOCAL_BACKUP)
        if got != new_want:
            print("ОТКАЗ: %s после записи %s != %s" % (rel, got, new_want)); return 1
    print("ГОТОВО: таблицы дедупликации выложены (%d файлов)" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
