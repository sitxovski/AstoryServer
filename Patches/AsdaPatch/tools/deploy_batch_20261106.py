# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_batch_20261106.py — ОБЩАЯ ВЫКЛАДКА 06.11.2026 одним перезапуском (слово владельца; выкладка — координатор).
#   Шаги при ОСТАНОВЛЕННОЙ стойке, по порядку:
#     1. deploy_p112.py                  — AsdaPatch v69 (несёт P111) во все GameServer;
#     2. deploy_n24.py                   — AddonNPC N24 во все NpcServer;
#     3. deploy_monster_ai_quests.py     — Monster.ai, 6 копий (md5 — NEW_MD5 deploy_monster_ai_quests.py);
#     4. deploy_item_names_20261106.py   — ItemName_Table.txt, 3 GameServer;
#     5. deploy_gift_as_buy_20261106.py  — item_table.txt и SellItemTable.txt, 3 GameServer.
#   Наборы файлов шагов не пересекаются (сверяется при запуске). До шагов — SpreadLimit равен в 6 папках (deploy_loot_exp_all.spread_ok).
#   Запуск: py -3.13 restart_stack.py --deploy deploy_batch_20261106.py --expect P112_PartyExpSpread --expect P111_HatchSupplement --expect N24_LowMobLoot
#   После старта: py -3.13 deploy_batch_20261106.py --check-started.
# Режимы: (без ключа) — сухой прогон всех шагов и таблица состояния; --apply — шаги по порядку; первый провал — автооткат НЕ делается, скрипт
#   называет шаг и останавливается (стойка остановлена, решает координатор: --rollback); в конце сверка md5 всех файлов и «ГОТОВО»;
#   --rollback — обратный порядок, только шаги, у которых на стойке есть новые файлы; затем сверка, что новых не осталось;
#   ASDA_BATCH_ROLLBACK=1 + --apply — то же через restart_stack; --check-started — проверки шагов и md5 при работающей стойке.
# Коды: 0 готово; 12 SpreadLimit разошёлся; 13 шаг не прошёл; 14 сверка итога не сошлась; 15 наборы файлов пересекаются.
# Журнал: tools/run_batch_20261106/deploy.log (дописывается).
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки
from deploy_p90 import rmd5                           # md5 файла стойки (только чтение)
import deploy_loot_exp_all as lootexp                 # сверка SpreadLimit
import deploy_p112 as p112                            # WANT_DLL, бэкап-суффикс
import deploy_n24 as n24                              # WANT
import deploy_monster_ai_quests as mon                # plan_files, NEW_MD5

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                       # корень стойки
LOG = os.path.join(HERE, "run_batch_20261106", "deploy.log")   # журнал выкладки


def manifest(folder):
    """Файлы манифеста шага: путь от v2 → (база, новый)."""
    m = json.load(open(os.path.join(HERE, folder, "manifest.json"), encoding="utf-8"))
    return {rel: (f["base"], f["new"]) for rel, f in m["files"].items()}


def steps():
    """[(скрипт, {файл от v2: новый md5}, есть ли --check-started)]."""
    p = {d + r"\AsdaPatch.dll": p112.WANT_DLL for d in stack_layout.GS_FOLDERS}
    n = {d + r"\AddonNPC.dll": n24.WANT for d in stack_layout.NPC_FOLDERS}
    m = {rel: mon.NEW_MD5[base] for rel, base in mon.plan_files().items()}
    i = {rel: f[1] for rel, f in manifest("data_item_names_20261106").items()}
    g = {rel: f[1] for rel, f in manifest("data_gift_as_buy_20261106").items()}
    return [("deploy_p112.py", p, True), ("deploy_n24.py", n, True), ("deploy_monster_ai_quests.py", m, False),
            ("deploy_item_names_20261106.py", i, True), ("deploy_gift_as_buy_20261106.py", g, True)]


def say(line):
    """Строка в консоль и журнал."""
    print(line, flush=True)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run(script, flag):
    """Шаг-скрипт с ключом → (код, вывод)."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + ([flag] if flag else []), capture_output=True, env=env, timeout=3600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    say("── %s %s: код %d\n%s" % (script, flag or "(сухой прогон)", p.returncode, out))
    return p.returncode, out


def state(plan):
    """Сколько файлов шага уже новые: (новых, всего)."""
    good = sum(1 for rel, want in plan.items() if rmd5(V2 + "\\" + rel) == want)
    return good, len(plan)


def table(all_steps):
    """Таблица состояния стойки; возвращает {скрипт: новых}."""
    res = {}
    for script, plan, _ in all_steps:
        good, total = state(plan)
        res[script] = good
        say("  %s: новых %d из %d" % (script, good, total))
    return res


def disjoint(all_steps):
    """Не пересекаются ли наборы файлов шагов."""
    seen = {}
    for script, plan, _ in all_steps:
        for rel in plan:
            if rel.lower() in seen:
                say("СТОП: %s есть и в %s, и в %s" % (rel, seen[rel.lower()], script))
                return False
            seen[rel.lower()] = script
    say("наборы файлов шагов не пересекаются: всего файлов %d" % len(seen))
    return True


def main():
    """Точка входа."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_BATCH_ROLLBACK") == "1")
    apply = apply and not rollback
    check = "--check-started" in sys.argv
    say("== deploy_batch_20261106 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
        "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    all_steps = steps()
    if not disjoint(all_steps):
        return 15
    if check:
        bad = [s for s, _, c in all_steps if c and run(s, "--check-started")[0] != 0]
        st = table(all_steps)
        full = all(st[s] == len(p) for s, p, _ in all_steps)
        good = lootexp.spread_ok() and not bad and full
        say("ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ: шаги %s, все файлы новые: %s" % (bad, full)))
        return 0 if good else 14
    if rollback:
        st = table(all_steps)
        for s, _, _ in reversed(all_steps):
            if st[s] == 0:
                say("  %s: новых файлов нет — откатывать нечего" % s)
                continue
            rc, _ = run(s, "--rollback")
            if rc != 0:
                say("СТОП: откат %s не прошёл (код %d)" % (s, rc))
                return 13
        left = table(all_steps)
        if any(left.values()):
            say("СВЕРКА: после отката остались новые файлы — смотри таблицу")
            return 14
        say("ГОТОВО: откат выполнен, новых файлов на стойке нет. Нужен старт стойки.")
        return 0
    if not lootexp.spread_ok():
        return 12
    if not apply:
        bad = [s for s, _, _ in all_steps if run(s, "")[0] != 0]
        table(all_steps)
        say("сухой прогон: %s" % ("все шаги готовы к --apply" if not bad else "НЕ ГОТОВО: %s" % ", ".join(bad)))
        return 13 if bad else 0
    for s, _, _ in all_steps:
        rc, out = run(s, "--apply")
        if rc != 0 or "ГОТОВО" not in out:
            say("СТОП: шаг %s не прошёл (код %d). Уже выложенное откатывает --rollback." % (s, rc))
            table(all_steps)
            return 13
    st = table(all_steps)
    if not all(st[s] == len(p) for s, p, _ in all_steps):
        say("СВЕРКА: не все файлы новые — смотри таблицу, откат --rollback")
        return 14
    say("ГОТОВО: общая выкладка 06.11 — все шаги, сверка md5 %d файлов сошлась. Дальше старт стойки и --check-started."
        % sum(len(p) for _, p, _ in all_steps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
