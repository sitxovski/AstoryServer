# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_relay_gift.py — обёртка P101 §3 (5076 через RelayServer ×3 и ChannelManager телом 237 б) под контракт
#   restart_stack.py --deploy (02.11.2026, cash-gift-relay, ревизия REVIEW_RELAY.md B1/B2).
#   Байтовый патч и выкладка — AstoryServer\Patches\RelayGift\patch_relay_gift.py (mode_remote / mode_rollback / mode_dry).
#
# Контракт restart_stack.py: ищет скрипт в этой папке, зовёт «python deploy_relay_gift.py --apply» ПОСЛЕ остановки стойки,
#   ждёт код 0 и «ГОТОВО» в выводе; затем stack_parity --sync (сверяет exe копии Ch2_* с stack_layout.EXE_MD5).
#   Запуск: python restart_stack.py --deploy deploy_relay_gift.py  (объявление и перезапуск — сам restart_stack).
# Режимы:
#   (без ключей)  СУХОЙ ПРОГОН: mode_dry (живые копии → _live_copies, патч копий, md5) + показ правки EXE_MD5 без записи.
#                 «ГОТОВО» НЕ печатается.
#   --apply       mode_remote (стойка обязана быть остановлена; всё или ничего) → EXE_MD5 в stack_layout.py на md5 «после»
#                 (точечно, бэкап stack_layout.py до правки, сверка повторным чтением) → «ГОТОВО». Сбой правки EXE_MD5 →
#                 откат exe на сервере (mode_rollback) и возврат stack_layout.py из бэкапа, код 1.
#   --rollback    [--date ГГГГММДД] mode_rollback (по умолчанию последний бэкап) → EXE_MD5 на md5 «до» → «ОТКАТ ГОТОВО».
# EXE_MD5: RelayServer и Indun_RelayServer 97cda850… ↔ a8cd94ba…, Ch2_RelayServer 1ceccf1a… ↔ 075c41a5….
#   ChannelManager в EXE_MD5 нет и не добавляется: stack_parity сверяет EXE_MD5 только у папок-копий TWINS (Ch2_*),
#   у ChannelManager копии нет — запись ничего бы не проверяла (md5 CM сверяет сам patch_relay_gift.py).
# Коды: 0 — успех, 1 — отказ. ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import datetime
import importlib.util
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))                                 # AsdaPatch\tools
RELAY_GIFT = os.path.normpath(os.path.join(HERE, "..", "..", "RelayGift", "patch_relay_gift.py"))   # байтовый патч
STACK_LAYOUT = os.path.join(HERE, "stack_layout.py")                              # реестр EXE_MD5
BACKUP_ROOT = r"@@ASTORY_DEV_ROOT@@\_backup"                                               # локальные бэкапы до правки
EXE_KEYS = [r"RelayServer\RelayServer.exe", r"Indun_RelayServer\RelayServer.exe", r"Ch2_RelayServer\RelayServer.exe"]


def load(path, name):
    """Модуль из файла под своим именем (без кэша sys.modules)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def exe_md5_plan(pg, target):
    """Пары ключ → (md5 «до», md5 «после») и нужное значение для target ('after'|'before')."""
    want = dict(pg.TARGETS)
    out = {}
    for k in EXE_KEYS:
        b = want[k]
        out[k] = (b, pg.MD5_AFTER[b], pg.MD5_AFTER[b] if target == "after" else b)
    return out


def set_exe_md5(pg, target, log, dry=False):
    """Точечно заменить md5 трёх RelayServer в stack_layout.EXE_MD5 → путь бэкапа (или None, если правки нет/сухо).
    Каждая строка обязана нести «до» или «после», иначе отказ без записи. Сверка повторной загрузкой модуля."""
    text = open(STACK_LAYOUT, encoding="utf-8").read()
    new = text
    changed = []
    for k, (b, a, need) in exe_md5_plan(pg, target).items():
        pat = re.compile(r'(r"%s":\s*")([0-9a-f]{32})(")' % re.escape(k))
        m = pat.findall(new)
        if len(m) != 1:
            raise pg.PatchError("stack_layout.py: ключ %s найден %d раз (нужно 1)" % (k, len(m)))
        cur = m[0][1]
        if cur not in (b, a):
            raise pg.PatchError("stack_layout.py: %s = %s — ни «до», ни «после», чужая правка; не трогаю" % (k, cur))
        if cur != need:
            new = pat.sub(lambda mm: mm.group(1) + need + mm.group(3), new)
            changed.append((k, cur, need))
        log("  EXE_MD5[%s]: %s → %s%s" % (k, cur, need, "" if cur != need else " (уже)"))
    if dry or not changed:
        return None
    stamp = datetime.datetime.now()
    bk = os.path.join(BACKUP_ROOT, "%s_cashgift_relay_deploy" % stamp.strftime("%Y-%m-%d"), stamp.strftime("%H%M%S"),
                      "AstoryServer", "Patches", "AsdaPatch", "tools", "stack_layout.py")
    os.makedirs(os.path.dirname(bk), exist_ok=True)
    shutil.copy2(STACK_LAYOUT, bk)
    log("  бэкап stack_layout.py: %s" % bk)
    with open(STACK_LAYOUT, "w", encoding="utf-8", newline="") as f:
        f.write(new)
    ns = {"__file__": STACK_LAYOUT, "__name__": "stack_layout_check"}             # сверка по ТЕКСТУ файла: импорт мог бы
    exec(compile(open(STACK_LAYOUT, encoding="utf-8").read(), STACK_LAYOUT, "exec"), ns)   # взять устаревший .pyc
    for k, (b, a, need) in exe_md5_plan(pg, target).items():
        if ns["EXE_MD5"].get(k) != need:
            shutil.copy2(bk, STACK_LAYOUT)
            raise pg.PatchError("stack_layout.py: после записи EXE_MD5[%s] = %s ≠ %s — возвращён из бэкапа" % (k, ns["EXE_MD5"].get(k), need))
    return bk


def main(argv=None):
    """--apply / --rollback [--date] / без ключей — сухой прогон."""
    argv = sys.argv[1:] if argv is None else argv
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    pg = load(RELAY_GIFT, "patch_relay_gift")
    log = print
    try:
        if "--apply" in argv:
            log("P101 RelayGift: выкладка (стойка должна быть остановлена restart_stack-ом)")
            rows, date = pg.mode_remote(log)
            log("EXE_MD5 → «после»")
            try:
                set_exe_md5(pg, "after", log)
            except (pg.PatchError, OSError, subprocess.TimeoutExpired) as e:
                log("СБОЙ правки EXE_MD5: %s — откатываю exe на сервере (паритет иначе остановит стойку)" % e)
                pg.mode_rollback(date, log)
                raise
            log("ГОТОВО: exe выложены (%d), EXE_MD5 обновлён; бэкап v2\\_backup\\cashgift_relay_%s" % (len(rows), date))
        elif "--rollback" in argv:
            date = argv[argv.index("--date") + 1] if "--date" in argv else None
            pg.mode_rollback(date, log)
            log("EXE_MD5 → «до»")
            set_exe_md5(pg, "before", log)
            log("ОТКАТ ГОТОВО: exe и EXE_MD5 исходные; стойку НЕ перезапускал")
        else:
            pg.mode_dry(log)
            log("EXE_MD5 (сухо, без записи):")
            set_exe_md5(pg, "after", log, dry=True)
            log("СУХОЙ ПРОГОН обёртки OK: сервер и stack_layout.py не менялись")
    except (pg.PatchError, OSError, subprocess.TimeoutExpired) as e:
        log("ОТКАЗ: %s" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
