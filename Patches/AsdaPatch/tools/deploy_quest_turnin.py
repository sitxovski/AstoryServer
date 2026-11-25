# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_quest_turnin.py — ВЫКЛАДКА / ОТКАТ сдачи 16 непроходимых заданий + патча AddonNPC N22 ([ИСПРАВЛЕНИЕ] дефекта данных
#   оригинала, 31.10.2026, bug-quest-follow; решение владельца «Починить сервер», вариант «Б»; предел 10 ячеек NPC — патч N22).
#   В КАЖДОЙ папке NpcServer стойки (stack_layout.NPC_FOLDERS: NpcServer, Indun_NpcServer, Ch2_NpcServer):
#     Quest\QuestNpcTable.Bin    — +16 ячеек «ПРИНИМАЕТ» в свободных слотах ≤ 9 (задания 70, 72 ×2, 75, 85, 86, 113, 125, 126,
#                                  127, 129, 151, 154, 156, 157, 241), освобождена мёртвая 104/шаг 2 у Эллосы (56); формат 1774 б;
#     Quest\ConditionTable.Bin   — +17 условий (ключи 1148…1164; награды — строки RewardTable/RepayTable без ссылок);
#     Quest\QuestNpcTableExt.Bin — НОВЫЙ файл: таблица расширения (96/шаг 0 у Эллосы, слот 10, ключ 1164);
#     AddonNPC.dll               — + N22_QuestCellsExt (слоты 10…127 из таблицы расширения; Config 12→13, секция в patches.ini
#                                  дописывается самой DLL при старте, Enabled=1).
#   Файлы и проверка — tools/data_quest_turnin/ (генератор AstoryClient/Tools/asda_quest_turnin_restore.py) и
#   AddonNPC/out/AddonNPC.dll (verify_n22.py, stand_n22.py). Описание патча — Reports/bug_quest_follow/N22_PATCH_DESIGN.md.
#   ★ Выкладка — ТОЛЬКО вместе с выпуском клиента (страницы NSR сдачи, SNQInfo/SNQICT/QuestNpcTableExt клиента): сервер без
#   клиента ничего не ломает (клиент не покажет новых ячеек и не отправит их слот), но и ничего не даёт.
#   ★ python restart_stack.py --deploy deploy_quest_turnin.py ; после старта — python deploy_quest_turnin.py --check-started
#     (md5 всех файлов, процессы, строка N22 в PatchLog каждой папки NpcServer).
# Бэкап: <файл>.bak_20261031_turnin рядом, v2\_backup\2026-10-31_quest_turnin\…, @@ASTORY_DEV_ROOT@@\_backup\2026-10-31_bug-quest-follow\server\v2\…
#   (у нового QuestNpcTableExt.Bin бэкапа нет — его не было).
# Откат (--rollback; стойка остановлена): файлы из .bak_20261031_turnin; QuestNpcTableExt.Bin откладывается в
#   QuestNpcTableExt.Bin.removed_20261031_turnin (не удаляется); без него N22 не ставится («N22 не установлен» в PatchLog).
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
import deploy_p91 as base                                              # общие функции (SSH, бэкап, заливка) — без побочных эффектов
from deploy_p90 import rmd5, rbusy, rcopy, rdel, md5

V2 = base.V2
DATA = os.path.join(HERE, "data_quest_turnin")
DLL_DIR = os.path.join(HERE, "..", "..", "AddonNPC", "out")
NONE = "none"                       # rmd5 отсутствующего файла
_FILES = {   # путь в папке NpcServer → (локальный файл, md5 базы = живой стойки 31.10.2026, md5 нового)
    r"Quest\QuestNpcTable.Bin": (os.path.join(DATA, "QuestNpcTable.Bin"), "2e9e9666b292484c9fa25051a21e99aa", "fbc00b7e33be56db46e9b23b119b7ab6"),
    r"Quest\ConditionTable.Bin": (os.path.join(DATA, "ConditionTable.Bin"), "a2aca1a21b3012c7c3156e15460e470f", "d8495e2cc2fa377192febbaab99e16ad"),
    r"Quest\QuestNpcTableExt.Bin": (os.path.join(DATA, "QuestNpcTableExt.Bin"), NONE, "c88ca97a7f8d76d4751284f20e22c1a7"),
    r"AddonNPC.dll": (os.path.join(DLL_DIR, "AddonNPC.dll"), "c29b5b368efa5b631f9971dc6e08b336", "8295f65b59ad945d3a872462dc6072c5"),
}
FILES = {}       # путь на стойке → (локальный, база, новый); все папки NpcServer — из stack_layout
for _ns in stack_layout.NPC_FOLDERS:
    for _f, (_l, _b, _n) in _FILES.items():
        FILES[_ns + "\\" + _f] = (_l, _b, _n)
BUSY = [ns + r"\NpcServer.exe" for ns in stack_layout.NPC_FOLDERS]
REMOVED = ".removed_20261031_turnin"

base.SUFFIX = ".bak_20261031_turnin"
base.SRV_BACKUP = V2 + r"\_backup\2026-10-31_quest_turnin"
base.LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-31_bug-quest-follow/server/v2"
base.LOG = os.path.join(HERE, "run_quest_turnin_20261031_deploy", "deploy.log")
log, flush = base.log, base.flush


def patchlog_n22(ns):
    """PatchLog папки NpcServer — блок последнего запуска; (имя файла, вердикт, причины, [ВЫКЛ] прочих). Только чтение.
    ★ 31.10.2026 (fix-check-started): разбор вынесен в общий patchlog.py (здесь был образец: последний «Хост   :», «=== итог»,
    «[OK] N22_QuestCellsExt», провалы [MISMATCH]/[ОШИБКА]/[ERR]/[ВЫКЛ] N22/«не поддерживается»/MasterEnable=0) + PID работающего."""
    import patchlog
    name, text, pids, err = patchlog.read_folder(ns)    # по SSH, FileShare.ReadWrite, предел времени
    if err:
        return "нет журнала", False, [err], []
    ok, why, info = patchlog.judge(text, ["N22_QuestCellsExt"], pids=pids)
    return name, ok, why, [n for n in info["notes"] if n.startswith("прочий выключен")]


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    check = "--check-started" in sys.argv
    lines = []
    log(lines, "== deploy_quest_turnin (N22) %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                                     "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if check else "сухой прогон"))
    log(lines, "папки NpcServer (stack_layout): %s" % ", ".join(stack_layout.NPC_FOLDERS))
    try:
        if check:   # только чтение: md5 всех файлов = новый, процессы работают, в PatchLog каждой папки N22 установлен
            good = True
            for rel, (local, b, new) in FILES.items():
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: %s %s" % (rel, got, "новый" if got == new else "база" if got == b else "ЧУЖОЙ!"))
                good = good and got == new
            busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
            log(lines, "процессов NpcServer работает: %d из %d" % (len(busy), len(BUSY)))
            for ns in stack_layout.NPC_FOLDERS:
                name, ok_n22, why, off = patchlog_n22(ns)
                log(lines, "%s PatchLog %s (последний запуск): %s" % (ns, name, "N22 УСТАНОВЛЕН" if ok_n22 else "N22 НЕ УСТАНОВЛЕН"))
                for w in why:
                    log(lines, "    ! " + w)
                for o in off:
                    log(lines, "    (выключено настройкой) " + o)
                good = good and ok_n22
            good = good and len(busy) == len(BUSY)
            log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
            flush(lines)
            return 0 if good else 5
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if rollback:
            todo = [rel for rel, (l, b, new) in FILES.items() if rmd5(V2 + "\\" + rel) == new]
            if not todo:
                log(lines, "СТОП: на стойке нет новых файлов — откатывать нечего")
                flush(lines)
                return 9
            for rel in todo:
                if FILES[rel][1] == NONE:
                    continue
                bak = rmd5(V2 + "\\" + rel + base.SUFFIX)
                if bak != FILES[rel][1]:
                    log(lines, "СТОП: %s%s нет или это не база (%s)" % (rel, base.SUFFIX, bak))
                    flush(lines)
                    return 6
            for rel in todo:
                src = V2 + "\\" + rel
                if FILES[rel][1] == NONE:     # нового файла не было — откладываем, не удаляем
                    rcopy(src, src + REMOVED)
                    if rmd5(src + REMOVED) != FILES[rel][2]:
                        log(lines, "СТОП: копия %s%s не сошлась — файл не тронут" % (rel, REMOVED))
                        flush(lines)
                        return 4
                    rdel(src)
                    log(lines, "%s: отложен в %s, на месте %s" % (rel, rel + REMOVED, rmd5(src)))
                    continue
                rcopy(src + base.SUFFIX, src)
                got = rmd5(src)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got == FILES[rel][1] else "НЕ СОШЛОСЬ"))
                if got != FILES[rel][1]:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ. Нужен старт стойки (N22 без таблицы не встанет — PatchLog «N22 не установлен»; это и есть сток).")
            flush(lines)
            return 0
        # Шаг 1. Локальные файлы — ровно те, что проверены.
        log(lines, "шаг 1 — локальные файлы:")
        for f, (lp, b, new) in _FILES.items():
            got = md5(lp) if os.path.exists(lp) else NONE
            log(lines, "  %s: %s %s" % (f, got, "OK" if got == new else "НЕ ТОТ (ждали %s)" % new))
            if got != new:
                log(lines, "СТОП: перегенерировать (asda_quest_turnin_restore.py / AddonNPC build.bat + verify_n22)")
                flush(lines)
                return 3
        # Шаг 2. Стойка — каждый файл в каждой папке: база (или уже новый); новый файл таблицы обязан появиться ВЕЗДЕ.
        log(lines, "шаг 2 — стойка (%d файлов в %d папках):" % (len(FILES), len(stack_layout.NPC_FOLDERS)))
        # Образы NpcServer.exe — те, на которых сверены площадки N22 (verify_n22: живой c02486d6, Indun 0de2c559, Ch2 7f79b5da).
        for ns in stack_layout.NPC_FOLDERS:
            rel = ns + r"\NpcServer.exe"
            want = stack_layout.EXE_MD5[rel]
            got = rmd5(V2 + "\\" + rel)
            log(lines, "  %s: %s %s" % (rel, got, "OK" if got == want else "НЕ ТОТ (ждали %s)" % want))
            if got != want:
                log(lines, "СТОП: образ NpcServer другой — площадки N22 на нём не сверены, ничего не трогаю")
                flush(lines)
                return 8
        plan = []
        for rel, (lp, b, new) in FILES.items():
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "  %s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == new else new))
            if cur == new:
                continue
            if cur != b:
                log(lines, "СТОП: %s = %s, ожидалась база %s — ничего не трогаю" % (rel, cur, b))
                flush(lines)
                return 8
            plan.append((rel, lp, b, new))
        ext_missing = [ns for ns in stack_layout.NPC_FOLDERS
                       if not any(rel == ns + r"\Quest\QuestNpcTableExt.Bin" for rel, _, _, _ in plan)
                       and rmd5(V2 + "\\" + ns + r"\Quest\QuestNpcTableExt.Bin") != _FILES[r"Quest\QuestNpcTableExt.Bin"][2]]
        log(lines, "  таблица расширения: будет во всех папках NpcServer — %s" % ("ДА" if not ext_missing else "НЕТ: %s" % ext_missing))
        if ext_missing:
            flush(lines)
            return 8
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        # Шаг 3. План: бэкап (у кого была база) и заливка через временный файл со сверкой md5.
        log(lines, "шаг 3 — план (%d файлов):" % len(plan))
        for rel, lp, b, new in plan:
            log(lines, "  %s: %s, залить %s" % (rel, "бэкап " + rel + base.SUFFIX if b != NONE else "новый файл (бэкапа нет)", new))
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (%d файлов). Затем старт стойки и --check-started (PatchLog: строка N22)."
                % len(plan))
            flush(lines)
            return 0
        for rel, lp, b, new in plan:
            if b != NONE:
                base.backup_one(rel, lines)
            base.put(rel, lp, new, lines)
        log(lines, "ГОТОВО: выложено %d файлов. Старт стойки — restart_stack; затем python deploy_quest_turnin.py --check-started."
            % len(plan))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
