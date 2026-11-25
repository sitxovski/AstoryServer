# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_loot_exp_all.py — ОДНА выкладка лута, опыта и Monster.ai (06.11.2026, сессия pet-hatch-summon; замечание ревизии: без окна «только опыт»).
#   restart_stack берёт один --deploy, поэтому шаги идут здесь подряд при ОСТАНОВЛЕННОЙ стойке:
#     1. deploy_p112.py               — AsdaPatch v69 (несёт P111) во все GameServer;
#     2. deploy_n24.py                — AddonNPC N24 во все NpcServer;
#     3. deploy_monster_ai_quests.py  — Monster.ai (зачёт заданий только за их цель).
#   Перед шагами сверяется равенство SpreadLimit в [P112_PartyExpSpread] всех GS и [N24_LowMobLoot] всех NpcServer (нет секции — умолчание 10).
#   ★ Выкладка и рестарт — ТОЛЬКО координатор по слову владельца:
#     py -3.13 restart_stack.py --deploy deploy_loot_exp_all.py --expect P112_PartyExpSpread --expect P111_HatchSupplement --expect N24_LowMobLoot
#   После старта: py -3.13 deploy_loot_exp_all.py --check-started.
# Режимы: (без ключа) — сухой прогон всех шагов; --apply — шаги по порядку, первый провал останавливает (выложенное откатывает --rollback);
#   --rollback — обратный порядок; ASDA_LOOTEXP_ROLLBACK=1 + --apply — то же одним перезапуском; --check-started — проверки шагов 1–2 и SpreadLimit.
# Коды: 0 готово; 12 SpreadLimit разошёлся; 13 шаг не прошёл (его код — в выводе).
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                   # единый состав стойки
from deploy_p90 import rread, rmd5                    # общие функции SSH (только чтение)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                       # корень стойки
STEPS = ["deploy_p112.py", "deploy_n24.py", "deploy_monster_ai_quests.py"]   # порядок выкладки
CHECKED = ["deploy_p112.py", "deploy_n24.py"]         # у этих есть --check-started
DEFAULT_LIMIT = "10"                                  # умолчание SpreadLimit обеих DLL


def ini_limit(folder, section):
    """SpreadLimit секции section в patches.ini папки; нет файла/секции/ключа — умолчание."""
    path = V2 + "\\" + folder + r"\ConfigSet\patches.ini"
    if rmd5(path) == "none":
        return DEFAULT_LIMIT
    data = rread(path)
    text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("latin-1")
    cur = None
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip()
        elif cur == section and s.startswith("SpreadLimit") and "=" in s:
            return s.split("=", 1)[1].strip()
    return DEFAULT_LIMIT


def spread_ok():
    """Равен ли SpreadLimit во всех папках обеих частей (лут и опыт — одно определение)."""
    vals = {d: ini_limit(d, "P112_PartyExpSpread") for d in stack_layout.GS_FOLDERS}
    vals.update({d: ini_limit(d, "N24_LowMobLoot") for d in stack_layout.NPC_FOLDERS})
    print("SpreadLimit: " + ", ".join("%s=%s" % kv for kv in vals.items()), flush=True)
    if len(set(vals.values())) != 1:
        print("СТОП: SpreadLimit различается — лут и опыт разойдутся", flush=True)
        return False
    return True


def step(script, flag):
    """Шаг-скрипт с ключом flag → код возврата; вывод печатается."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    env.pop("ASDA_P112_ROLLBACK", None)
    cmd = [sys.executable, os.path.join(HERE, script)] + ([flag] if flag else [])
    p = subprocess.run(cmd, capture_output=True, env=env, timeout=3600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    print("── %s %s: код %d\n%s" % (script, flag or "(сухой прогон)", p.returncode, out), flush=True)
    return p.returncode, out


def main():
    """Точка входа."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_LOOTEXP_ROLLBACK") == "1")
    apply = apply and not rollback
    if "--check-started" in sys.argv:
        bad = [s for s in CHECKED if step(s, "--check-started")[0] != 0]
        good = spread_ok() and not bad
        print("ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ: %s" % (bad or "SpreadLimit")), flush=True)
        return 0 if good else 13
    if rollback:
        for s in reversed(STEPS):
            rc, _ = step(s, "--rollback")
            if rc != 0:
                print("СТОП: откат %s не прошёл (код %d)" % (s, rc), flush=True)
                return 13
        print("ГОТОВО: откат всех шагов, нужен старт стойки", flush=True)
        return 0
    if not spread_ok():
        return 12
    if not apply:
        bad = [s for s in STEPS if step(s, "")[0] != 0]
        print("сухой прогон: %s" % ("все шаги готовы к --apply" if not bad else "НЕ ГОТОВО: %s" % ", ".join(bad)), flush=True)
        return 13 if bad else 0
    for s in STEPS:
        rc, out = step(s, "--apply")
        if rc != 0 or "ГОТОВО" not in out:
            print("СТОП: шаг %s не прошёл (код %d) — откат выложенного: --rollback" % (s, rc), flush=True)
            return 13
    print("ГОТОВО: лут, опыт и Monster.ai выложены. Дальше старт стойки и --check-started.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
