# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_pet31.py — ВЫКЛАДКА / ОТКАТ строки 31 «SnowLion» в PetData_Info\PetInfo_Table.txt трёх GameServer стойки
#   (stack_layout.GS_FOLDERS: GameServer, Indun_GameServer, Ch2_GameServer; 29.10.2026, наш дефект: яйцо 76338 → порода 31,
#   а строк было 0–30 → 6103 код 8; Reports/pet31_snowlion/REPORT.md). Данные строит `build_pet31.py build`
#   (srv_out + manifest.json в tools/data_pet31/, стенд загрузчика). DLL не меняются. Путь 1:1 deploy_wod_items.py.
#   Выкладка и рестарт: python restart_stack.py --deploy deploy_pet31.py (объявление ботом за 3 минуты);
#     после старта (только чтение): python deploy_pet31.py --check-started
#   Сухой прогон (по умолчанию): сверка md5 базы на стойке и локальных новых файлов, ничего не пишет.
# Выкладка (--apply; GameServer ОСТАНОВЛЕНЫ): md5 базы каждого файла = manifest «base» (уже «new» — пропуск; чужой — СТОП, код 8)
#   → бэкап (<файл>.bak_<tag> рядом, v2\_backup\<tag>\…, @@ASTORY_DEV_ROOT@@\_backup6-10-29_pet31\server2\…) → заливка через
#   временный файл со сверкой md5.
# Откат (--rollback; GameServer остановлены): каждый файл, который сейчас = «new», — из <файл>.bak_<tag> (= «base»).
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                                    # единый состав стойки (3 GameServer)
from deploy_p90 import rmd5, rbusy, rcopy, rupload, rdel, rread, md5    # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
MANIFEST = os.path.join(HERE, "data_pet31", "manifest.json")   # путь → local / base / new (строит генератор)
LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"                              # локальные бэкапы: <корень>/<дата>_<группа>/server/v2
BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS]       # процессы, которые держат таблицы


def log(lines, line):
    """Строка в вывод и в журнал прогона."""
    print(line, flush=True)
    lines.append(line)


def flush(lines, tag):
    """Дописать журнал прогона в run_pet31_<tag>/deploy.log."""
    p = os.path.join(HERE, "run_pet31_%s" % tag, "deploy.log")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def local_backup_dir(tag):
    """@@ASTORY_DEV_ROOT_FWD@@/_backup/<ГГГГ-ММ-ДД>_<группа>/server/v2 из метки 20261029_pet31."""
    d, _, g = tag.partition("_")
    return "%s/%s-%s-%s_%s/server/v2" % (LOCAL_BACKUP_ROOT, d[:4], d[4:6], d[6:8], g or "pet31")


def backup_one(rel, tag, lines):
    """Бэкап файла стойки рядом (.bak_<tag>), в v2\\_backup\\<tag> и локально; существующие не перезаписываются."""
    src = V2 + "\\" + rel
    want = rmd5(src)
    for dst in (src + ".bak_" + tag, V2 + "\\_backup\\" + tag + "\\" + rel):
        have = rmd5(dst)
        if have == "none":
            rcopy(src, dst)
            have = rmd5(dst)
            if have != want:
                raise RuntimeError("бэкап %s не сошёлся (%s ≠ %s)" % (dst, have, want))
            log(lines, "  бэкап: %s %s" % (dst, want))
        elif have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
    loc = local_backup_dir(tag) + "/" + rel.replace("\\", "/")
    if os.path.exists(loc):
        if md5(loc) != want:
            raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл" % loc)
        return
    data = rread(src)
    os.makedirs(os.path.dirname(loc), exist_ok=True)
    with open(loc, "wb") as f:
        f.write(data)
    if md5(loc) != want:
        raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".pet31_upload"
    rupload(local, up)
    if rmd5(up) != want:
        rdel(up)
        raise RuntimeError("залитый %s не сошёлся по md5 — %s не тронут" % (up, dst))
    rcopy(up, dst)
    rdel(up)
    got = rmd5(dst)
    log(lines, "  %s выложено: %s %s" % (rel, got, "OK" if got == want else "НЕ СОШЛОСЬ"))
    if got != want:
        raise RuntimeError("после копии %s = %s, ожидался %s" % (dst, got, want))


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    check = "--check-started" in sys.argv
    man = json.load(open(MANIFEST, encoding="utf-8"))
    tag, files = man["tag"], man["files"]
    lines = []
    log(lines, "== deploy_pet31 %s %s (метка %s, файлов %d)" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else
        "ПРОВЕРКА СТАРТА" if check else "сухой прогон", tag, len(files)))
    if set(rel.split("\\")[0] for rel in files) != set(stack_layout.GS_FOLDERS):
        log(lines, "СТОП: манифест покрывает %s, а GameServer стойки — %s (пересобери: build_pet31.py build)"
            % (sorted(set(rel.split("\\")[0] for rel in files)), stack_layout.GS_FOLDERS))
        flush(lines, tag)
        return 3
    try:
        if check:   # только чтение: файлы = новые, процессы работают
            good = True
            for rel, f in files.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый" if got == f["new"] else "база" if got == f["base"] else "ЧУЖОЙ!"))
                good = good and got == f["new"]
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "GameServer работает: %d из %d" % (len(busy), len(BUSY)))
            ok = good and len(busy) == len(BUSY)
            log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if ok else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
            flush(lines, tag)
            return 0 if ok else 5
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines, tag)
            return 2
        if rollback:
            todo = [rel for rel, f in files.items() if rmd5(V2 + "\\" + rel) == f["new"]]
            if not todo:
                log(lines, "СТОП: на стойке нет новых файлов — откатывать нечего")
                flush(lines, tag)
                return 9
            for rel in todo:
                bak = rmd5(V2 + "\\" + rel + ".bak_" + tag)
                if bak != files[rel]["base"]:
                    log(lines, "СТОП: %s.bak_%s нет или это не база (%s)" % (rel, tag, bak))
                    flush(lines, tag)
                    return 6
            for rel in todo:
                rcopy(V2 + "\\" + rel + ".bak_" + tag, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got == files[rel]["base"] else "НЕ СОШЛОСЬ"))
                if got != files[rel]["base"]:
                    flush(lines, tag)
                    return 4
            log(lines, "ОТКАТ ГОТОВ. Нужен старт стойки.")
            flush(lines, tag)
            return 0
        plan = []
        for rel, f in files.items():
            lp = os.path.join(HERE, f["local"])
            if not os.path.exists(lp) or md5(lp) != f["new"]:
                log(lines, "СТОП: %s нет или md5 не %s (пересобери: build_pet31.py build)" % (lp, f["new"]))
                flush(lines, tag)
                return 3
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == f["new"] else f["new"]))
            if cur == f["new"]:
                continue
            if cur != f["base"]:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю (снимок устарел: build_pet31.py "
                           "fetch + build)" % (rel, cur, f["base"]))
                flush(lines, tag)
                return 8
            plan.append((rel, lp, f["new"]))
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines, tag)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (%d файлов)" % len(plan))
            flush(lines, tag)
            return 0
        for rel, lp, new in plan:
            backup_one(rel, tag, lines)
            put(rel, lp, new, lines)
        log(lines, "ГОТОВО: строка 31 PetInfo_Table выложена (%d файлов в %d GameServer). Старт стойки — restart_stack.py; "
                   "затем python deploy_pet31.py --check-started."
            % (len(plan), len(stack_layout.GS_FOLDERS)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines, tag)
        return 7
    flush(lines, tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
