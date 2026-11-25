# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_gear_fix_20261107.py — ИСПРАВЛЕНИЕ ДАННЫХ СНАРЯЖЕНИЯ (07.11.2026, пачка 11, баги 3 и 5; сессия booster-loot). Отчёт и таблица —
#   Reports/gear_fix_20261107/ (audit.csv: предмет → что есть → что должно быть → источник).
#   ПРИЧИНА. Шаблоны снаряжения сервера и клиента — разные линии данных. У эталона Interlude вещи (Pirate Lieutenant/Captain, Vampire,
#   Jack's Halloween, WorldCup и др.) — грейд 3 (Hero) или 2, а строки item_table/SowelCombine сервера (и стока) — грейд-ряд ниже: одна
#   группа статов (+22 = 0), предел улучшения 6, совел «Особый». Клиент обещает Hero и 8, а вещь создаётся по серверной строке:
#   статы — группы item_table +18/+22 (ток.10/13), совел — пара SowelCombine ток.22/23, предел +26 ← +146 (ток.44).
#   ПРАВКА (класс A, 1101 код; значения — только эталон и чистые образцы сервера того же типа/подтипа/уровня/групп):
#     item_table.txt   ток.10, 13 := группы эталона (Interlude item_list @104/@116); ток.41 (+67) := Interlude запись +224;
#     SowelCombine.txt ток.22 совел, 42 цена сброса, 43 очки, 44 предел, 45 грейд-класс, 46 грейд свитка, 48, 49 группы опций,
#                      55, 56 := значения образца (оба токена пишутся в одно поле +166, чтений этого поля в декомпиле нет) (у строк с пределом 0 колонки 42/43/46/55/56 пусты, свиток сверяется с +150).
#   Класс B (156 кодов, в стоке предел 0: Indian/Starry/Celestial Swim/Spooky) — ключ --with-limit0 при --build, слово владельца 07.11 «Включить».
#   Удочки 69658… (7 кодов) не входят: образец — лук, pricetable 0, данных нет (target_B_rods_excluded.json).
#   Класс C (подтверждённые коды class_c.csv, цель target_C.json) — ключ --with-class-c при --build, слово владельца 07.11 «Да, разобрать».
#   Слоты (цель target_S.json, таблица Reports/gear_fix_20261107/slots_diff.csv) — ключ --with-slots при --build, слова владельца 07.11 «Да, привести»,
#   «Да, расширить»: item_table токены 3, 6, 7, 16, 17 := клиент и эталон; значения ступени как у прежних волн. Цены 25, 26 и уровень не меняются.
#   Итоговая волна 07.11 (ревизия): --with-slots-only (target_slots_only.json), --with-analog (target_analog.json), --with-slots-armor (target_slots_armor.json),
#   --with-fixes (target_final_fixes.json: Spooky токен 3 и c42, 73350/73351 без бонуса). Цели накладываются поле за полем в этом порядке. --build без ключей отказывает;
#   набор ключей пишется в манифест (поле keys). --with-bonus (target_bonus.json): токены 51–54 := pricetable dw06–dw09, слово владельца 07.11 «Да, заполнить».
#   Таблицы читаются при старте GameServer — нужен рестарт. Уже выданные вещи не меняются (статы и совел — в строке dbo.Item; предел
#   сервер поднимает сам при перемещении вещи, sub_4C97C0). БД этот скрипт не трогает. Клиент: ведомость OptionGroup0/1 — отдельно
#   (Reports/gear_fix_20261107/apply_client_optgroups.py), выпускать вместе, иначе окно опций 50300 покажет старые группы.
#   ★ Выкладка и рестарт — ТОЛЬКО координатор: python restart_stack.py --deploy deploy_gear_fix_20261107.py
#   python deploy_gear_fix_20261107.py --build [--with-limit0] [--with-class-c] [--with-slots] [--with-slots-only] [--with-analog] [--with-slots-armor] [--with-fixes] [--with-bonus] — снимок таблиц по SSH (только чтение) → data_gear_fix/srv_out + манифест md5
#   python deploy_gear_fix_20261107.py                         — сухой прогон (md5 базы на стойке = манифесту; ничего не пишет)
#   --apply (GameServer ОСТАНОВЛЕНЫ) / --rollback / --check-started — общий путь deploy_premium_boxes.py (те же функции).
# Модуль без побочных эффектов при импорте.
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки (все GameServer)
import deploy_premium_boxes as DPB                    # бэкап/заливка/откат/проверка старта (без побочных эффектов)

DATA = os.path.join(HERE, "data_gear_fix")            # снимок, выход, манифест этой правки
TAG = "20261107_gearfix"                              # суффикс бэкапов стойки .bak_<tag>
REPORT = r"@@ASTORY_DEV_ROOT@@\Reports\gear_fix_20261107"   # таблицы целей аудита
IT_REL = "ItemTable_Info\\item_table.txt"             # шаблоны предметов
SC_REL = "ItemTable_Info\\SowelCombine.txt"           # заточка и совел
IT_MAP = {3: "t3", 6: "t6", 7: "t7", 10: "g0", 13: "g1", 16: "t16", 17: "t17", 18: "t18", 19: "t19", 20: "t20", 27: "t27", 28: "t28", 32: "t32", 33: "t33", 40: "t40", 41: "v41"}   # токен item_table → поле цели (t* есть только у слотов)
SC_MAP = {22: "sow", 42: "c42", 43: "c43", 44: "lim", 45: "gc", 46: "c46", 48: "o48", 49: "o49", 51: "s51", 52: "s52", 53: "s53", 54: "s54", 55: "c55", 56: "c56"}   # токен SowelCombine → поле цели
SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"        # ключ SSH
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"             # стойка
SRV_ROOT = "@@ASTORY_SERVER_ROOT_FWD@@/Working_ASDA/v2"                  # корень стойки


def md5(path):
    """md5 файла."""
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def scp_get(rel, dst):
    """Снимок файла стойки (только чтение) → dst; возврат md5."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    src = "%s:%s/%s" % (SSH_HOST, SRV_ROOT, rel.replace("\\", "/"))
    p = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", src, dst], capture_output=True, timeout=600)
    if p.returncode != 0:
        raise SystemExit("ОТКАЗ: scp %s: %s" % (rel, p.stderr.decode("utf-8", "replace")[-200:]))
    return md5(dst)


def patch_line(line, tmap, tgt):
    """Заменить токены строки по карте, сохранив разделители байт в байт. Возврат новой строки (bytes)."""
    parts = re.split(rb"(\s+)", line)          # чётные индексы — токены, нечётные — разделители
    if parts and parts[0] == b"":
        parts = parts[2:]                      # ведущих пробелов в таблицах нет; на всякий случай
    for tok, field in tmap.items():
        if field in tgt:                       # поля слотов есть не у всех целей
            parts[2 * tok] = str(tgt[field]).encode()
    return b"".join(parts)


def patch_file(src, dst, tmap, targets):
    """Правка таблицы: только строки целей и только токены карты. Сверка: изменены ровно эти строки, число строк то же."""
    data = open(src, "rb").read()
    lines = data.split(b"\r\n")
    left = dict(targets)
    changed = 0
    for i in range(1, len(lines)):
        head = lines[i].split(None, 1)
        if not head:
            continue
        code = head[0].decode("latin1")
        t = left.pop(code, None)
        if t is None:
            continue
        new = patch_line(lines[i], tmap, t)
        if len(new.split()) != len(lines[i].split()):
            raise SystemExit("ОТКАЗ: %s код %s — изменилось число токенов" % (src, code))
        if new != lines[i]:
            lines[i] = new
            changed += 1
    if left:
        raise SystemExit("ОТКАЗ: %s — нет строк кодов %s" % (src, sorted(left)[:5]))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(b"\r\n".join(lines))
    a = data.split(b"\r\n")
    o = open(dst, "rb").read().split(b"\r\n")
    if len(a) != len(o):
        raise SystemExit("ОТКАЗ: %s — изменилось число строк" % dst)
    diff = sum(1 for x, y in zip(a, o) if x != y)
    if diff != changed:
        raise SystemExit("ОТКАЗ: %s — изменено %d строк, ждали %d" % (dst, diff, changed))
    return changed


KEYS = (("--with-limit0", "target_B.json"), ("--with-class-c", "target_C.json"), ("--with-slots", "target_S.json"), ("--with-slots-only", "target_slots_only.json"),
        ("--with-analog", "target_analog.json"), ("--with-slots-armor", "target_slots_armor.json"), ("--with-fixes", "target_final_fixes.json"), ("--with-bonus", "target_bonus.json"))   # порядок наложения


def build(keys):
    """Снимки таблиц всех GameServer, точечная правка, манифест md5. keys — ключи целей из KEYS."""
    targets = {k: dict(v) for k, v in json.load(open(os.path.join(REPORT, "target_A.json"), encoding="utf-8")).items()}
    for key, fn in KEYS:
        if key in keys:
            for code, tgt in json.load(open(os.path.join(REPORT, fn), encoding="utf-8")).items():
                targets.setdefault(code, {}).update(tgt)   # поле за полем: поправки не стирают прежние значения
    print("кодов к правке: %d (ключи: %s)" % (len(targets), " ".join(keys)))
    files = {}
    for d in stack_layout.GS_FOLDERS:
        for rel, tmap in ((IT_REL, IT_MAP), (SC_REL, SC_MAP)):
            full = d + "\\" + rel
            name = os.path.basename(rel)
            loc_in = os.path.join(DATA, "srv_in", d, name)
            base = scp_get(full, loc_in)
            loc_out = os.path.join(DATA, "srv_out", d, name)
            n = patch_file(loc_in, loc_out, tmap, targets)
            print("%-52s %s → %s  строк %d" % (full, base, md5(loc_out), n))
            files[full] = {"local": os.path.relpath(loc_out, HERE).replace("\\", "/"), "base": base, "new": md5(loc_out)}
    man = {"tag": TAG, "keys": list(keys), "files": files}
    with open(os.path.join(DATA, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    print("манифест: %s (файлов %d)" % (os.path.join(DATA, "manifest.json"), len(files)))


def main():
    """--build; иначе общий путь deploy_premium_boxes по своему манифесту."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        keys = [k for k, _fn in KEYS if k in sys.argv]
        if not keys:
            raise SystemExit("ОТКАЗ: --build без ключей целей; нужен хотя бы один из: %s" % " ".join(k for k, _fn in KEYS))
        build(keys)
        return 0
    DPB.MANIFEST = os.path.join(DATA, "manifest.json")
    DPB.LOCAL_BACKUP_ROOT = "@@ASTORY_DEV_ROOT_FWD@@/_backup"
    return DPB.main()


if __name__ == "__main__":
    sys.exit(main())
