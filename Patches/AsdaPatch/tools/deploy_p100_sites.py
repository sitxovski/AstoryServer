# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p100_sites.py — ВРЕМЕННАЯ МЕРА до P102 (02.11.2026, решение координатора): в ConfigSet\patches.ini каждого GameServer
#   стойки (stack_layout.GS_FOLDERS) в секции [P100_ChargeStack] меняется ТОЛЬКО значение Sites: -1 → -32769 (= 0xFFFF7FFF,
#   все пути, кроме бита 15 «B5 аукцион покупка/снятие»). Причина — ошибка P100 v57 на 9906 при нескольких лотах (отчёт
#   Reports/item_dedup/charges/P102_PHASE1 в MEMANTO p102-dll): спецпредмет с аукциона ложится в новую ячейку, как в стоке.
#   Проверено стендом tools/stand_p102/stand_p102_b (gs_live и gs_stock + AsdaPatch v58 80b8d21b, STAND_P100_SITES=-32769):
#   113 OK / 0 провалов, 9 аукционных сценариев = сток по подписи. Остальные пути: SiteOn(bit) проверяет каждый бит отдельно.
#   P100 читает ini при старте — выкладка при ОСТАНОВЛЕННОЙ стойке (restart_stack.py --deploy deploy_p100_sites.py).
# Файл — UTF-16LE с BOM, CRLF (так его пишет Config.cpp). Скрипт читает ЖИВОЙ файл в момент запуска (его могли дописать другие
#   выкладки), меняет одну строку, проверяет, что остальные байты те же, пишет через srv_io.put_live (бэкапы: рядом
#   <файл>.bak_p100sites_20261102, v2\_backup\p100sites_20261102, локально RE/dumps/p100_sites_backup) и сверяет md5.
#   Без ключей — сухой прогон (ничего не пишет). --apply — запись («ГОТОВО» только при чистой проверке на всех GS).
#   --rollback — Sites -32769 → -1 тем же способом (возврат бита 15; ставится вместе с P102).
# Без побочных эффектов при импорте.
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
SECTION = "[P100_ChargeStack]"
OLD, NEW = "-1", "-32769"            # было / стало (0xFFFFFFFF → 0xFFFF7FFF)
TAG = "p100sites_20261102"
SRV_BACKUP = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2\_backup\\" + TAG
LOCAL_BACKUP = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "RE", "dumps", "p100_sites_backup"))


def change(raw, frm, to):
    """Байты ini → (новые байты, отчёт) или (None, причина отказа). Меняется ровно одна строка Sites= в секции P100."""
    if not raw.startswith(b"\xff\xfe"):
        return None, "нет BOM UTF-16LE"
    text = raw[2:].decode("utf-16-le")
    lines = text.split("\r\n")
    sec = [i for i, l in enumerate(lines) if l.strip() == SECTION]
    if len(sec) != 1:
        return None, "секция %s найдена %d раз" % (SECTION, len(sec))
    i = sec[0] + 1
    hits = []
    while i < len(lines) and not lines[i].strip().startswith("["):
        if re.match(r"\s*Sites\s*=", lines[i]):
            hits.append(i)
        i += 1
    if len(hits) != 1:
        return None, "строк Sites= в секции: %d" % len(hits)
    k = hits[0]
    cur = lines[k].split("=", 1)[1].strip()
    if cur == to:
        return raw, "уже Sites=%s" % to
    if cur != frm:
        return None, "Sites=%s, ожидалось %s — не трогаю" % (cur, frm)
    new_lines = list(lines)
    new_lines[k] = "Sites=%s" % to
    data = b"\xff\xfe" + "\r\n".join(new_lines).encode("utf-16-le")
    # сверка: отличается ровно одна строка
    diff = [j for j in range(len(lines)) if lines[j] != new_lines[j]]
    if diff != [k] or len(new_lines) != len(lines):
        return None, "внутренняя ошибка сверки строк"
    return data, "строка %d: Sites=%s → Sites=%s" % (k + 1, frm, to)


def main():
    import srv_io
    import stack_layout
    sys.stdout.reconfigure(encoding="utf-8")
    apply = "--apply" in sys.argv
    frm, to = (NEW, OLD) if "--rollback" in sys.argv else (OLD, NEW)
    plan, bad = [], 0
    for gs in stack_layout.GS_FOLDERS:
        rel = gs + "/ConfigSet/patches.ini"
        raw = srv_io.read_live(rel)
        live = srv_io.live_md5(rel)
        if hashlib.md5(raw).hexdigest() != live:
            print("  ОТКАЗ %s: прочитанное не сходится с живым md5" % gs); bad += 1; continue
        data, why = change(raw, frm, to)
        if data is None:
            print("  ОТКАЗ %s: %s" % (gs, why)); bad += 1; continue
        print("  %-18s md5 %s → %s  %s" % (gs, live[:8], hashlib.md5(data).hexdigest()[:8], why))
        if data != raw:
            plan.append((rel, data))
    if bad:
        print("ОТКАЗ: %d GS не прошли проверку — ничего не записано" % bad); return 1
    if not apply:
        print("сухой прогон: к записи %d файлов (--apply при остановленной стойке через restart_stack.py)" % len(plan)); return 0
    for rel, data in plan:
        want = hashlib.md5(data).hexdigest()
        got = srv_io.put_live(rel, data, ".bak_" + TAG, SRV_BACKUP, LOCAL_BACKUP)
        if got != want:
            print("ОТКАЗ: %s после записи %s ≠ %s" % (rel, got, want)); return 1
        back, _ = change(srv_io.read_live(rel), frm, to)
        if back is None or back != data:
            print("ОТКАЗ: %s — повторное чтение не подтверждает Sites=%s" % (rel, to)); return 1
    print("ГОТОВО: [P100_ChargeStack] Sites=%s на %d GS (бит 15 B5 аукцион %s)" % (to, len(plan) or len(stack_layout.GS_FOLDERS),
          "выключен" if to == NEW else "включён"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
