# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_booster_shop.py — ВЫКЛАДКА / ОТКАТ белого списка покупок `ItemTable_Info\SellItemTable.txt` под витрину бустер-шопа
#   (05.11.2026, задача владельца «редактор бустер-шопа»). Данные строит редактор витрины `Tools/BoosterShopEditor`
#   (кнопка «Сохранить» или `bse_cli.py server-out`): srv_out + manifest.json в tools/data_booster_shop/. Инструкция —
#   `Tools/BoosterShopEditor/README.md`.
#   Зачем: GameServer списка витрины не имеет — `CharChargeShopBuy@0x511DA0` (GameServer.c:104581) продаёт любой код из
#   SellItemTable.txt (шапка «макс_код<TAB>число», загрузчик GameServer.c:68424). Новый бустер витрины без строки в белом
#   списке сервер не продаст (5071 код 0). Файл — во ВСЕХ GameServer стойки (stack_layout.GS_FOLDERS). Цена — item_table ток.26,
#   её этот скрипт НЕ меняет (редактор проверяет равенство цене клиента).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор по слову владельца: python restart_stack.py --deploy deploy_booster_shop.py
#     после старта (только чтение): python deploy_booster_shop.py --check-started
#   Сухой прогон (по умолчанию): сверка md5 базы на стойке и локальных новых файлов, ничего не пишет.
#   Выкладка (--apply; GameServer ОСТАНОВЛЕНЫ): md5 базы = manifest «base» (уже «new» — пропуск; чужой — СТОП, код 8)
#     → бэкап (<файл>.bak_<tag>, v2\_backup\<tag>\…, @@ASTORY_DEV_ROOT@@\_backup\<дата>_<группа>\server\v2\…) → заливка через
#     временный файл со сверкой md5. Общие функции бэкапа/заливки — из deploy_premium_boxes (тот же порядок).
#   Откат (--rollback; GameServer остановлены): каждый файл, который сейчас = «new», — из <файл>.bak_<tag> (= «base»).
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                                    # единый состав стойки (3 GameServer)
from deploy_p90 import rmd5, rbusy, rcopy, md5                         # общие функции SSH (без побочных эффектов)
from deploy_premium_boxes import backup_one, put, V2                   # бэкап и заливка с проверкой md5 (без побочных эффектов)

MANIFEST = os.path.join(HERE, "data_booster_shop", "manifest.json")   # путь стойки → local / base / new (строит редактор)
BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS]       # процессы, которые держат таблицы
# Что этот скрипт вправе менять: белый список покупок и (05.11.2026, бустеры, созданные редактором) запись предмета,
#   строка SowelCombine (её счёт обязан равняться item_table) и строка состава GachaItemRateTable — во всех GameServer.
TABLES = ("SellItemTable.txt", "item_table.txt", "SowelCombine.txt", "GachaItemRateTable.txt")
ALLOWED = {d + "\\ItemTable_Info\\" + t for d in stack_layout.GS_FOLDERS for t in TABLES}


def log(lines, line):
    """Строка в вывод и в журнал прогона."""
    print(line, flush=True)
    lines.append(line)


def flush(lines, tag):
    """Дописать журнал прогона в run_booster_shop_<tag>/deploy.log."""
    p = os.path.join(HERE, "run_booster_shop_%s" % tag, "deploy.log")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    """Сухой прогон / --apply / --rollback / --check-started по манифесту редактора."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    check = "--check-started" in sys.argv
    if not os.path.isfile(MANIFEST):
        print("СТОП: нет %s — сохрани витрину в редакторе (bse_cli.py server-out)" % MANIFEST)
        return 3
    man = json.load(open(MANIFEST, encoding="utf-8"))
    tag, files = man["tag"], man["files"]
    lines = []
    log(lines, "== deploy_booster_shop %s %s (метка %s, файлов %d)" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else
        "ПРОВЕРКА СТАРТА" if check else "сухой прогон", tag, len(files)))
    extra = set(files) - ALLOWED
    if extra:
        log(lines, "СТОП: манифест трогает чужие файлы %s (разрешены только %s в GameServer стойки)" % (sorted(extra), TABLES))
        flush(lines, tag)
        return 3
    # Паритет канала 2: копия обязана получить ровно то же, что поле (stack_parity сверит после выкладки).
    for twin, field in stack_layout.TWINS.items():
        for t in TABLES:
            a, b = files.get(twin + "\\ItemTable_Info\\" + t), files.get(field + "\\ItemTable_Info\\" + t)
            if twin in stack_layout.GS_FOLDERS and (a is None) != (b is None) or (a and b and a["new"] != b["new"]):
                log(lines, "СТОП: %s и %s получают разный %s — паритет канала 2 нарушится (пересобери в редакторе)" % (twin, field, t))
                flush(lines, tag)
                return 3
    if not files:
        log(lines, "СТОП: манифест пуст — витрина не требует правки сервера")
        flush(lines, tag)
        return 8
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
                log(lines, "СТОП: %s нет или md5 не %s (пересохрани витрину в редакторе)" % (lp, f["new"]))
                flush(lines, tag)
                return 3
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == f["new"] else f["new"]))
            if cur == f["new"]:
                continue
            if cur != f["base"]:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю (снимок устарел: bse_cli.py fetch-server, "
                           "затем пересохранить витрину)" % (rel, cur, f["base"]))
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
        log(lines, "ГОТОВО: таблицы витрины бустеров выложены (%d файлов). Старт стойки — за координатором; затем "
                   "python deploy_booster_shop.py --check-started." % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines, tag)
        return 7
    flush(lines, tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
