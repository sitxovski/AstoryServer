# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_premium_boxes.py — ВЫКЛАДКА / ОТКАТ серверных таблиц премиум-коробок «предмет ×N» (26.10.2026, первый набор —
#   песок 20931 ×100/×1000/×10000, коды 79719…79721, пакеты 5518…5520). Данные строит
#   `AstoryClient/Tools/asda_premium_box_add.py build` (srv_out + manifest.json в tools/data_premium_boxes/); рецепт —
#   `Docs/Port/systems/PREMIUM_ITEM_ADD_FLOW.md`. Файлы: ItemTable_Info\{item_table, SowelCombine, PackageItem_Table,
#   SellItemTable}.txt во ВСЕХ GameServer стойки (stack_layout.GS_FOLDERS: GameServer, Indun_GameServer, Ch2_GameServer).
#   DLL и шлюз gp7 не меняются: шлюз перечитывает item_table.txt сам (fileChanged), карта premium_item_map.json не нужна.
#   ★ 02.11.2026 (коробка функционального предмета под прежней позицией витрины — «Зелье повышения уровня» 558 → 79935,
#     Reports/levelup_potion): манифест может содержать и gp7-server\premium_item_map.json — шлюз перечитывает её сам
#     по изменению файла; заливается тем же путём (база → бэкап → временный файл → md5), откат так же.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_premium_boxes.py
#     после старта (только чтение): python deploy_premium_boxes.py --check-started
#   Сухой прогон (по умолчанию): сверка md5 базы на стойке и локальных новых файлов, ничего не пишет.
# Выкладка (--apply; GameServer ОСТАНОВЛЕНЫ): md5 базы каждого файла = manifest «base» (уже «new» — пропуск; чужой — СТОП, код 8)
#   → бэкап (<файл>.bak_<tag> рядом, v2\_backup\<tag>\…, @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_sandsets\server\v2\…) → заливка через
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
MANIFEST = os.path.join(HERE, "data_premium_boxes", "manifest.json")   # путь → local / base / new (строит генератор)
LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"                              # локальные бэкапы: <корень>/<дата>_<группа>/server/v2
BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS]       # процессы, которые держат таблицы


def busy_for(files):
    """★ 19.11.2026 (админ-центр А4.0): что проверяется на занятость для манифеста → (exe, файлы). exe — GameServer.exe всех
    GameServer (как прежде, BUSY) + NpcServer.exe каждой копии NpcServer, чьи файлы есть в манифесте (Monster.ai, Quest\\*,
    Skill\\* и т. п. держит NpcServer, а не GameServer); файлы — сами файлы манифеста (IsBusy открывает файл без общего доступа:
    занят ЛЮБЫМ процессом — «BUSY»). Перед --apply/--rollback свободно должно быть всё; --check-started ждёт работающие exe."""
    exes = list(BUSY)
    for rel in files:
        root = rel.split("\\")[0]
        if root in stack_layout.NPC_FOLDERS and root + r"\NpcServer.exe" not in exes:
            exes.append(root + r"\NpcServer.exe")
    return exes, sorted(files)


def check_roots(files):
    """Годен ли состав манифеста → None или текст СТОП. По умолчанию (премиум-коробки): ровно все GameServer + карта шлюза.
    Обёртки (deploy_changeset.py) подменяют своей проверкой."""
    roots = set(rel.split("\\")[0] for rel in files)
    extra = {rel for rel in files if not rel.startswith(tuple(d + "\\" for d in stack_layout.GS_FOLDERS))}
    if roots - {"gp7-server"} != set(stack_layout.GS_FOLDERS) or extra - {"gp7-server\\premium_item_map.json"}:
        return ("манифест покрывает %s, а GameServer стойки — %s (пересобери: asda_premium_box_add.py build)"
                % (sorted(roots), stack_layout.GS_FOLDERS))
    return None


def log(lines, line):
    """Строка в вывод и в журнал прогона."""
    print(line, flush=True)
    lines.append(line)


def flush(lines, tag):
    """Дописать журнал прогона в run_premium_boxes_<tag>/deploy.log."""
    p = os.path.join(HERE, "run_premium_boxes_%s" % tag, "deploy.log")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def local_backup_dir(tag):
    """@@ASTORY_DEV_ROOT_FWD@@/_backup/<ГГГГ-ММ-ДД>_<группа>/server/v2 из метки 20261026_sandsets."""
    d, _, g = tag.partition("_")
    return "%s/%s-%s-%s_%s/server/v2" % (LOCAL_BACKUP_ROOT, d[:4], d[4:6], d[6:8], g or "premium_boxes")


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
    up = dst + ".pbox_upload"
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
    log(lines, "== deploy_premium_boxes %s %s (метка %s, файлов %d)" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else
        "ПРОВЕРКА СТАРТА" if check else "сухой прогон", tag, len(files)))
    why = check_roots(files)
    if why:
        log(lines, "СТОП: " + why)
        flush(lines, tag)
        return 3
    exes, held = busy_for(files)                                       # ★ 19.11.2026 А4.0: занятость по путям манифеста
    try:
        if check:   # только чтение: файлы = новые, процессы работают
            good = True
            for rel, f in files.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый" if got == f["new"] else "база" if got == f["base"] else "ЧУЖОЙ!"))
                good = good and got == f["new"]
            busy = [rel for rel in exes if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, ("GameServer работает: %d из %d" if exes == BUSY else "процессы стойки (GameServer/NpcServer) работают: %d из %d")
                % (len(busy), len(exes)))
            ok = good and len(busy) == len(exes)
            log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if ok else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
            flush(lines, tag)
            return 0 if ok else 5
        busy = [rel for rel in exes if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        held_busy = []                                                 # файл держит любой процесс (не только exe стойки)
        for rel in held:
            if rbusy(V2 + "\\" + rel) == "BUSY":
                held_busy.append(rel)
                log(lines, "  занят (файл открыт процессом): " + rel)
        if held_busy and not (apply or rollback):
            # ★ ревизия 33 М-3: таблицы процессы стойки после загрузки закрывают (fopen/fclose) — занятый файл виден уже в сухом
            #   прогоне на ПК, ДО объявления и остановки (иначе стойка осталась бы лежать после отказа --apply)
            log(lines, "СТОП (сухой прогон): файлы набора открыты процессом — выкладка встанет после остановки; разберитесь до рестарта")
            flush(lines, tag)
            return 2
        busy += held_busy
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
                log(lines, "СТОП: %s нет или md5 не %s (пересобери: asda_premium_box_add.py build)" % (lp, f["new"]))
                flush(lines, tag)
                return 3
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == f["new"] else f["new"]))
            if cur == f["new"]:
                continue
            if cur != f["base"]:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю (снимок устарел: asda_premium_box_add.py "
                           "fetch-server + build)" % (rel, cur, f["base"]))
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
        log(lines, "ГОТОВО: таблицы премиум-коробок выложены (%d файлов в %d GameServer). Старт стойки — за координатором; "
                   "затем python deploy_premium_boxes.py --check-started и asda_premium_box_add.py verify-live."
            % (len(plan), len(stack_layout.GS_FOLDERS)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines, tag)
        return 7
    flush(lines, tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
