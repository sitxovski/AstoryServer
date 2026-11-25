# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_changeset.py — ВЫКЛАДКА / ОТКАТ серверной половины НАБОРА ИЗМЕНЕНИЙ админ-центра Astory (волна А3 «Данные: магазины»,
#   19.11.2026; AstoryAdminCenter/domains/shopcs.py). Это ТОНКАЯ ОБЁРТКА deploy_premium_boxes.py — порядок тот же и код тот же:
#   сухой прогон (по умолчанию: md5 базы на стойке = manifest «base», локальные новые файлы = «new»), --apply (GameServer ОСТАНОВЛЕНЫ;
#   база ≠ — СТОП код 8; бэкап <файл>.bak_<tag> + v2\_backup\<tag> + @@ASTORY_DEV_ROOT@@\_backup\<дата>_<группа>\server\v2; заливка через
#   временный файл со сверкой md5), --rollback (из .bak_<tag>), --check-started (только чтение).
#   Отличие одно: манифест — из переменной окружения ASDA_CHANGESET_MANIFEST (его строит `asda_admin.py changeset …` в
#   AstoryAdminCenter/data/changesets/cs<№>/manifest.json). restart_stack.py зовёт выкладчик с --apply и передаёт ему своё
#   окружение, поэтому выкладка набора — штатная команда:
#       ASDA_CHANGESET_MANIFEST=<манифест> python restart_stack.py --deploy deploy_changeset.py
#   ASDA_CHANGESET_MODE=rollback превращает --apply в --rollback (откат тем же рестартом с объявлением); по успеху печатается
#   «ГОТОВО» — restart_stack.py без него стойку не запускает.
#   ★ 20.11.2026 ревизия 39 Н-3: ASDA_CHANGESET_GUARD (JSON-команда от панели) — перепроверка набора ПОСЛЕ остановки, до копирования;
#   отказ — «СТОП: перепроверка набора после остановки стойки…», код 10, файлы не тронуты (post_stop_guard).
#   Что вправе менять: ItemTable_Info\{item_table, SellItemTable, PackageItem_Table, GachaItemRateTable, PrimiumGaChaTable,
#   PrimiumGaChaPriceTable, HonorPrice_Table, HairTypeTable, Cellob_Table, RepayTable, LimitationQuest}.txt, MonsterData_Info\Monster.ai
#   NpcData_Info\LimitationQuest.txt и ConfigSet\FameInfo.txt (★ А4.6) во всех GameServer стойки (stack_layout.GS_FOLDERS) и таблицы NpcServer из NPC_TABLES
#   (Monster\Monster.ai, MiningItemTable\*.mng, Quest\ и NpcInfo\LimitationQuest.txt) во всех NpcServer; ★ А4.8: MapData_Info\MapWarpCost.txt
#   во всех GameServer и MapData_Info\OpenMapInfo.ini только в копиях поля (GameServer + Ch2_GameServer; у Indun файла нет).
#   ★ А5.5: ini наших DLL — ConfigSet\patches.ini у GameServer ×3 / NpcServer ×3 / LoginManager, DBManager\ConfigSet\dbpatch.ini,
#   ConfigSet\srvdbpatch.ini у RelayServer ×3 + ItemRelayServer + OperationServer (пары «поле = Ch2» вместе) и ini\Collection.ini NpcServer ×3.
#   Остальное — СТОП, код 3.
#   ★ 19.11.2026 (админ-центр А4.0): занятость — по путям манифеста (deploy_premium_boxes.busy_for: GameServer.exe, NpcServer.exe
#   копий с файлами манифеста и сами файлы — любой процесс, держащий файл); база md5 — своя у КАЖДОЙ копии (Indun не затирается
#   файлом поля); каждая таблица — во всех копиях своей семьи. Подмена base.check_roots живёт до конца процесса (выкладчик
#   запускается отдельным процессом; в песочнице панели — восстанавливается).
# Модуль без побочных эффектов при импорте.
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                                    # единый состав стойки (3 GameServer)
import deploy_premium_boxes as base                                    # выкладчик с манифестом (без побочных эффектов)

TABLES = ("item_table.txt", "SellItemTable.txt", "PackageItem_Table.txt", "GachaItemRateTable.txt", "PrimiumGaChaTable.txt",
          "PrimiumGaChaPriceTable.txt",
          "HonorPrice_Table.txt", "HairTypeTable.txt",                  # ★ 19.11.2026 А4.1: магазин чести, парикмахерская
          "Cellob_Table.txt",                                           # ★ 20.11.2026 А4.4: уровень самоцвета (cs_kinds/itemdata.py)
          "RepayTable.txt",                                             # ★ 20.11.2026 А4.5: награды заданий (cs_kinds/questtables.py)
          "LimitationQuest.txt")                                        # ★ А4.5: копия доски ItemTable_Info (GS её не читает — держим = прочим)
# ★ 20.11.2026 А4.3 «Монстры и добыча» (AstoryAdminCenter/domains/cs_kinds/monsters.py): Monster.ai во всех GameServer
#   (MonsterData_Info) и во всех NpcServer (Monster), таблицы копания NpcServer MiningItemTable\<ServerName_NNN ini\MapInfo.ini><тип>.mng
#   (24 карты dev 19.11 × 2 типа ini\Collection.ini; = monsters.MINING_MAPS — самотест панели сверяет оба списка). Размер файлов
#   панель не меняет (правка на месте); NpcServer и GameServer читают их только при старте — выкладка рестартом стойки.
#   ★ 20.11.2026 ревизия 35 К-5: имена — в РЕГИСТРЕ ФАЙЛОВ НА ДИСКЕ стойки (листинг SSH, 3 NpcServer одинаковы), а не MapInfo.ini
#   (castle_of_chess, Lostvalley, t_palace_of_queen, t_castle_of_chess, flabis, castle_of_chaos) — заливка и .bak_* под тем же именем.
MINING_MAPS = ("Sillaris", "Rein", "Conquester", "Alpen", "Night_Valley", "Lostvalley", "SunnyCoast", "Flammio", "palace_of_queen",
               "castle_of_chess", "t_palace_of_queen", "t_castle_of_chess", "MountainFlamion", "flabis", "StagnantDesert", "DragonLaiR",
               "firewayforest", "castle_of_chaos", "Inferion", "battlefield", "eventfield", "fieldofhonor", "quizstage", "^MineWar^")
# ★ 20.11.2026 А4.5 «Задания»: доска объявлений LimitationQuest.txt — 4 копии в каждой паре папок (GameServer NpcData_Info — читает GS,
#   ItemTable_Info — не читается; NpcServer Quest — читает NpcServer, NpcInfo — не читается), все 12 одинаковы (b19a88ed, deploy_board_quest
#   28.10) — панель держит их одинаковыми. Размер строк не меняется по смыслу (правка чисел на месте), вставок нет.
# ★ 20.11.2026 А4.6 «Звания» (AstoryAdminCenter/domains/cs_kinds/titledata.py): ConfigSet\FameInfo.txt во всех GameServer (загрузчик
#   sub_4A18F0 читает его только при старте; правка чисел на месте — очки, включено, условия, бонусы; число записей и номера не меняются).
# ★ 20.11.2026 А4.7 «Навыки и классы» (AstoryAdminCenter/domains/cs_kinds/skilldata.py): SkillTable_Info\SkillInfo.sif (числа уровня,
#   макс. уровень, требование дерева; правка байтов на месте, размер не меняется) и SkillPointTable.spt (порог), ConfigSet\ClassStat.txt и
#   ExpTable.txt (числа на месте) во всех GameServer; Skill\Skillinfo.sif во всех NpcServer (та же база — NpcServer.exe.c:10068).
GS_EXTRA = ("MonsterData_Info\\Monster.ai", "NpcData_Info\\LimitationQuest.txt", "ConfigSet\\FameInfo.txt",
            "SkillTable_Info\\SkillInfo.sif", "SkillTable_Info\\SkillPointTable.spt", "ConfigSet\\ClassStat.txt", "ConfigSet\\ExpTable.txt",
            "MapData_Info\\MapWarpCost.txt",                            # ★ А4.8: цены телепорта кристаллом (у Indun своя база)
            "Event\\GameServerEvent.txt")                               # ★ А5.4: счастливые часы (sub_4190E0 — только при старте; одна база ×3)
# ★ 20.11.2026 А4.8 «Карты» (AstoryAdminCenter/domains/cs_kinds/mapdata.py): MapData_Info\MapWarpCost.txt (матрица цен N×N, правка
#   числа на месте) во всех GameServer; MapData_Info\OpenMapInfo.ini (Use карты, правка числа на месте) — ТОЛЬКО в копиях поля
#   (GameServer и его пара Ch2 по stack_layout.TWINS): Indun_GameServer работает без этого файла (byte_5F5EF6 = 0, GameServer.c:64923),
#   появление файла у Indun изменило бы его поведение. Оба читаются только при старте — выкладка рестартом стойки.
GS_FIELD_ONLY = ("MapData_Info\\OpenMapInfo.ini",)
FIELD_GS = [d for d in stack_layout.GS_FOLDERS if d == stack_layout.GS_FOLDERS[0]
            or stack_layout.TWINS.get(d) == stack_layout.GS_FOLDERS[0]]
# ★ 19.11.2026 А4.0: таблицы NpcServer (подпуть от папки копии) — по мере областей реестра видов панели
NPC_TABLES = (("Monster\\Monster.ai",) + tuple("MiningItemTable\\%s%02d.mng" % (m, t) for m in MINING_MAPS for t in range(2))
              + ("Quest\\LimitationQuest.txt", "NpcInfo\\LimitationQuest.txt")            # ★ А4.5
              + ("Skill\\Skillinfo.sif",))                                                 # ★ А4.7
GS_SUBS = {"ItemTable_Info\\" + t for t in TABLES} | set(GS_EXTRA)
# ★ 21.11.2026 А5.5 «patches.ini и конфиги» (AstoryAdminCenter/domains/cs_kinds/patchcfg.py): ini НАШИХ DLL — читаются только при
#   старте процесса (DllMain → Config::Init → MergeMissing → установка), правка значения на месте (кодировка, BOM, концы строк, комментарии
#   и Version — как были). Копии и пары: GameServer / NpcServer — парами «поле = Ch2» (Indun может отдельно — у него своя база),
#   srvdbpatch.ini — RelayServer ×3 (пара RelayServer = Ch2_RelayServer) + ItemRelayServer + OperationServer, LoginManager и DBManager —
#   по одной копии. Стоковый ini\Collection.ini NpcServer ×3 (CollectionTypeAniTime<NN>) — во всех NpcServer.
DLL_INI = {"ConfigSet\\patches.ini": list(stack_layout.GS_FOLDERS) + list(stack_layout.NPC_FOLDERS) + ["LoginManager"],
           "ConfigSet\\dbpatch.ini": ["DBManager"],
           "ConfigSet\\srvdbpatch.ini": list(stack_layout.RELAY_FOLDERS) + ["ItemRelayServer", "OperationServer"]}
NPC_TABLES = NPC_TABLES + ("ini\\Collection.ini",)
ALLOWED = ({d + "\\" + sub for d in stack_layout.GS_FOLDERS for sub in GS_SUBS}
           | {d + "\\" + sub for d in stack_layout.NPC_FOLDERS for sub in NPC_TABLES}
           | {d + "\\" + sub for d in FIELD_GS for sub in GS_FIELD_ONLY}                # ★ А4.8
           | {d + "\\" + sub for sub, ds in DLL_INI.items() for d in ds})              # ★ А5.5
# процесс копии → exe, который держит её файлы (занятость перед --apply / --rollback, проверка старта)
EXE_OF = {"LoginManager": "LoginManager\\LoginManager.exe", "DBManager": "DBManager\\DBManager.exe",
          "ItemRelayServer": "ItemRelayServer\\ItemRelayServer.exe", "OperationServer": "OperationServer\\OperationServer.exe"}
EXE_OF.update({d: d + "\\RelayServer.exe" for d in stack_layout.RELAY_FOLDERS})


def _dll_groups(sub, roots):
    """★ А5.5: группы копий ini DLL. Годно: все копии из своего процесса, пары «поле — Ch2» (stack_layout.TWINS) — обе или ни одной."""
    allowed = set(DLL_INI[sub])
    if not roots <= allowed:
        return "ini %s правится не у тех копий: %s" % (sub, sorted(roots - allowed))
    for twin, field in stack_layout.TWINS.items():
        if (twin in roots) != (field in roots):
            return "ini %s: %s без пары %s — паритет Ch2 (restart_stack код 6)" % (sub, twin if twin in roots else field,
                                                                                  field if twin in roots else twin)
    return None


def check_roots(files):
    """★ 19.11.2026 А4.0 (вместо проверки deploy_premium_boxes «ровно все GameServer»): каждый путь — из ALLOWED, и каждая таблица
    правится во ВСЕХ копиях своей семьи (все GameServer или все NpcServer; Ch2 = поле, Indun — своей базой из манифеста)."""
    bad = sorted(r for r in files if r not in ALLOWED)
    if bad or not files:
        return "манифест меняет недопустимое или пуст: %s" % bad[:5]
    by_sub = {}
    for rel in files:
        root, sub = rel.split("\\", 1)
        by_sub.setdefault(sub, set()).add(root)
    for sub, roots in sorted(by_sub.items()):
        if sub in DLL_INI:                                             # ★ А5.5: ini DLL — парами по процессам
            why = _dll_groups(sub, roots)
            if why:
                return why
            continue
        fam = stack_layout.NPC_FOLDERS if roots & set(stack_layout.NPC_FOLDERS) else stack_layout.GS_FOLDERS
        if sub in GS_FIELD_ONLY:                                       # ★ А4.8: таблица копий поля (у Indun файла нет)
            fam = FIELD_GS
        if roots != set(fam):
            return "таблица %s правится не во всех копиях: %s, а нужно %s" % (sub, sorted(roots), fam)
    return None


_BASE_BUSY_FOR = base.busy_for


def busy_for(files):
    """★ А5.5: занятость = прежняя (GameServer.exe всех GS + NpcServer.exe копий из манифеста + сами файлы) + exe LoginManager /
    DBManager / RelayServer / ItemRelayServer / OperationServer, чьи ini есть в манифесте."""
    exes, held = _BASE_BUSY_FOR(files)
    for rel in files:
        exe = EXE_OF.get(rel.split("\\")[0])
        if exe and exe not in exes:
            exes.append(exe)
    return exes, held


def post_stop_guard():
    """★ 20.11.2026 ревизия 39 Н-3 (админ-центр): ASDA_CHANGESET_GUARD — JSON-список команды перепроверки набора (её ставит
    shopcs._restart: python asda_admin.py changeset guard N …). restart_stack.py зовёт выкладчик с --apply ПОСЛЕ объявления и остановки,
    поэтому перепроверка здесь закрывает окно «проверка → 3 минуты объявления → остановка» (игроки могли повысить навык, добрать опыт).
    Код 0 — можно копировать (None); иначе / сбой запуска — причина (файлы не трогаются, restart_stack.py останавливается кодом 4,
    панель поднимает прежнюю стойку --start-only). Переменной нет — перепроверки нет (прежнее поведение, ручная выкладка)."""
    raw = os.environ.get("ASDA_CHANGESET_GUARD", "")
    if not raw:
        return None
    import subprocess
    try:
        argv = json.loads(raw)
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            return "ASDA_CHANGESET_GUARD — не список строк команды"
        p = subprocess.run(argv, capture_output=True, timeout=900, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    except Exception as ex:
        return "перепроверка не запустилась (%s)" % str(ex)[:200]
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    if p.returncode == 0:
        return None
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    why = [ln[len("ПРИЧИНА:"):].strip() for ln in lines if ln.startswith("ПРИЧИНА:")] or lines[-3:] or ["код %d" % p.returncode]
    return "; ".join(why)[:1500]                    # «; » — панель переводит каждую причину отдельно (i18n.tr)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    man = os.environ.get("ASDA_CHANGESET_MANIFEST", "")
    if not man or not os.path.isfile(man):
        print("СТОП: нет манифеста набора (ASDA_CHANGESET_MANIFEST=%r) — его строит asda_admin.py changeset server-dry" % man)
        return 3
    files = json.load(open(man, encoding="utf-8")).get("files") or {}
    why = check_roots(files)
    if why:
        print("СТОП: манифест %s: %s" % (man, why))
        return 3
    base.MANIFEST = man
    base.check_roots = check_roots                                     # ★ А4.0: семьи копий вместо «ровно все GameServer»
    base.busy_for = busy_for                                           # ★ А5.5: exe LoginManager / DBManager / Relay … по путям манифеста
    # ★ ревизия 30 К-5: журнал прогона — рядом с манифестом набора (данные панели), а не в run_premium_boxes_<tag>/ депо Perforce
    logdir = os.path.dirname(os.path.abspath(man))

    def flush(lines, tag):
        with open(os.path.join(logdir, "deploy.log"), "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    base.flush = flush
    rollback = os.environ.get("ASDA_CHANGESET_MODE") == "rollback"
    if rollback and "--apply" in sys.argv:
        sys.argv = [("--rollback" if a == "--apply" else a) for a in sys.argv]
    if "--apply" in sys.argv or "--rollback" in sys.argv:
        why = post_stop_guard()
        if why:
            print("СТОП: перепроверка набора после остановки стойки не прошла — файлы не тронуты: %s" % why)
            return 10
    rc = base.main()
    if rollback and rc == 0 and "--rollback" in sys.argv:
        print("ГОТОВО: серверная половина набора откачена из .bak (метка манифеста); старт стойки — restart_stack.py")
    return rc


if __name__ == "__main__":
    sys.exit(main())
