# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p124.py — P124_CostumeSowel: выкладка исправленного SowelCombine.txt (10.11.2026, баг владельца «Особый костюм
#   ангела - Нимб» L70 Hero несёт «Редкий камень шлема [60]» вместо сауэла грейда и уровня вещи). номер P124 выдан координатором 10.11;
#   сам скрипт ничего не выкладывает без --apply, а --apply запускает только координатор.
#
# Что меняется: только код сауэла в первой паре встроенных сауэлов (токен 22 = +60, GameServer.c:65203-65210) у 597
#   хвостовых вещей (коды > 76314). Встроенный сауэл разыгрывается при создании вещи: sub_4B7B00@0x4B7B00
#   (GameServer.c:73474). Ожидаемый код — по стоковому семейству вещи (то же имя и слот): Нимб L40 -> 9941 «Уник. [40]»,
#   L60 -> 9977 «Уник. [60]», значит L70 -> 10837 «Уникальный камень шлема [70]». Сборка и сверка:
#   Reports/costume_sowel_2026-11-10/audit_embedded_sowel.py (--fix, --fits), ведомость mismatch_live.csv.
# Источник ошибки: волна 31.10 Reports/armor_capacity/build_sowel_fill.py --include all (правило категории, «ближайший
#   уровень ниже»: яруса L70 в стоке нет -> «Редкий [60]/[40]»).
#
# Сервер читает SowelCombine.txt один раз при старте, поэтому выкладка идёт только через перезапуск стойки с объявлением:
#     python restart_stack.py --deploy @@ASTORY_DEV_ROOT@@\AstoryServer\Patches\AsdaPatch\tools\deploy_p124.py
# Площадки — stack_layout.GS_FOLDERS. Без --apply — сухой прогон. --rollback — вернуть live_in.
# Защита: запись только если на КАЖДОЙ площадке лежит ожидаемый исходный файл (md5 ORIG), иначе отказ (пересобрать).
# Уже выданные экземпляры (Joy1.dbo.Item) этим скриптом не меняются: отдельный SQL
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data_costume_sowel_20261110")
REL = "ItemTable_Info/SowelCombine.txt"           # путь файла от папки GameServer
ORIG_MD5 = "0ce8d2f3b7e2b456b0be267eb257328a"     # живой до правки (P115, снят 10.11.2026, одинаков на 3 GS)
FIXED_MD5 = "bda2e9c80bda705b76a9f462c298b222"    # data_costume_sowel_20261110/srv_out/SowelCombine.txt


def md5b(b):
    """md5 байтов (hex)."""
    return hashlib.md5(b).hexdigest()


def main():
    sys.path.insert(0, HERE)
    import srv_io          # noqa: E402  запись стойки только по SSH, с бэкапами
    import stack_layout    # noqa: E402  единый список папок стойки
    rollback = "--rollback" in sys.argv
    orig = open(os.path.join(DATA, "live_in", "SowelCombine.txt"), "rb").read()
    fixed = open(os.path.join(DATA, "srv_out", "SowelCombine.txt"), "rb").read()
    if md5b(orig) != ORIG_MD5 or md5b(fixed) != FIXED_MD5:
        print("ОТКАЗ: локальные файлы не совпадают со сборкой (%s / %s)" % (md5b(orig), md5b(fixed)))
        return 1
    src, dst = (fixed, orig) if rollback else (orig, fixed)
    live = {gs: srv_io.live_md5(gs + "/" + REL) for gs in stack_layout.GS_FOLDERS}
    for gs, m in live.items():
        print("  %-18s сейчас %s" % (gs, m))
    if all(m == md5b(dst) for m in live.values()):
        print("ГОТОВО: на всех площадках уже нужный файл (%s)" % md5b(dst))
        return 0
    wrong = [gs for gs, m in live.items() if m not in (md5b(src), md5b(dst))]
    if wrong:
        print("ОТКАЗ: на %s лежит неожиданный файл (не исходный и не целевой) — таблицу меняли, сборку повторить" % wrong)
        return 1
    if "--apply" not in sys.argv:
        print("сухой прогон: будет записано %s (%d б) на %s; запись — с --apply" % (md5b(dst), len(dst), stack_layout.GS_FOLDERS))
        return 0
    stamp = time.strftime("%Y%m%d_%H%M")
    suffix = (".bak_p124_rollback_" if rollback else ".bak_p124_") + stamp
    srv_bak = "@@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\_backup\\p124_" + stamp
    for gs in stack_layout.GS_FOLDERS:
        print("площадка %s:" % gs)
        srv_io.put_live(gs + "/" + REL, dst, suffix, srv_bak, os.path.join(DATA, "live_backup_" + stamp))
    bad = [gs for gs in stack_layout.GS_FOLDERS if srv_io.live_md5(gs + "/" + REL) != md5b(dst)]
    if bad:
        print("ОТКАЗ: после записи md5 не сошёлся на %s" % bad)
        return 1
    print("ГОТОВО: SowelCombine.txt %s на %s" % (md5b(dst), ", ".join(stack_layout.GS_FOLDERS)))
    return 0


if __name__ == "__main__" or globals().get("__spec__") is None:
    sys.exit(main())
