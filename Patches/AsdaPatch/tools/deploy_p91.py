# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p91.py — ВЫКЛАДКА / ОТКАТ волны exprate, часть 2 (решения владельца 26.10) ОДНИМ рестартом стойки:
#   • AsdaPatch P91 [ИСПРАВЛЕНИЕ] — потолок опыта за моба (1/9 уровня) × max(1, fEvent + LuckyHours); GameServer + Indun_GameServer;
#     секцию [P91_ExpCapRate] (Enabled/CapDivisor=9/CapScalesWithRate=1/SoloSite/PartySite) DLL дописывает в ini сама;
#   • Monster.ai — опыт 36 мобов Inferion (1 → F(ур.) стока), рейдовых копий боссов 752–757 и Йети 240/241 (1 → семейство × F),
#     «Блуждающий иллюминатик» 115 (582 → 456) — во ВСЕХ 4 папках (NpcServer\Monster, Indun_NpcServer\Monster,
#     GameServer\MonsterData_Info, Indun_GameServer\MonsterData_Info); меняется только поле опыта +0x35 у 45 записей
#     (генератор и проверка закономерности: tools/p91_monster_exp.py validate / apply; файлы — tools/data_p91/…).
#   Разбор: Reports/exprate/MOB_EXP_AUDIT.md §8–§9. ★ Выкладка и рестарт — ТОЛЬКО координатор:
#     python restart_stack.py --deploy deploy_p91.py --expect P91_ExpCapRate
#   после старта (только чтение): python deploy_p91.py --check-started
#
# Выкладка (--apply; только при ОСТАНОВЛЕННЫХ GameServer/Indun_GameServer/NpcServer/Indun_NpcServer):
#   1. md5 собранной DLL = WANT_DLL, файлов data_p91 = WANT_AI[папка]; md5 GameServer.exe обеих папок = e7b4ac38.
#   2. Процессы не держат файлы (занят — код 2).
#   3. На стойке AsdaPatch.dll = PREV_DLL, Monster.ai = BASE_AI[папка] (или уже новые — тогда этот файл пропускается).
#      Иначе — СТОП, код 8, ничего не тронуто.
#   4. Бэкап каждого заменяемого файла и обоих patches.ini GameServer: рядом <файл>.bak_20261026_p91, на сервере
#      v2\_backup\2026-10-26_p91\…, локально @@ASTORY_DEV_ROOT@@\_backup\2026-10-26_exprate\server\v2\…; сверка md5.
#   5. Заливка scp во временный <файл>.p91_upload (md5), копия поверх, сверка.
# Откат (--rollback; при остановленных процессах): каждый файл, который сейчас = новый, — из <файл>.bak_20261026_p91.
#   Быстро без замены: [P91_ExpCapRate] Enabled=0 (или CapScalesWithRate=0) + рестарт GameServer/Indun.
import base64
import hashlib
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # ★ 26.10.2026: единый состав стойки (канал 2: Ch2_*) — Reports/channel2/PLAN.md §5
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/AsdaPatch/out/AsdaPatch.dll"
WANT_DLL = "f88f0a2fe8fa87e94555c93c933e0e9c"                    # AsdaPatch v54 (P01…P89) + P91
PREV_DLL = {"7e7cf2a38327fa3a1ab7981f368f03d8": "AsdaPatch v54 P01…P89 (живая на 26.10)"}
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"
DATA = os.path.join(HERE, "data_p91")
AI = {   # путь на стойке (от v2) → (локальный новый, md5 базы на стойке, md5 нового)
    r"NpcServer\Monster\Monster.ai":              ("NpcServer/Monster/Monster.ai", "7d85891732be6bea055271e3c98bb2fe", "b05d93eac22cccf12f6c691b87ca57fa"),
    r"Indun_NpcServer\Monster\Monster.ai":        ("Indun_NpcServer/Monster/Monster.ai", "7d85891732be6bea055271e3c98bb2fe", "b05d93eac22cccf12f6c691b87ca57fa"),
    r"GameServer\MonsterData_Info\Monster.ai":    ("GameServer/MonsterData_Info/Monster.ai", "7d85891732be6bea055271e3c98bb2fe", "b05d93eac22cccf12f6c691b87ca57fa"),
    r"Indun_GameServer\MonsterData_Info\Monster.ai": ("Indun_GameServer/MonsterData_Info/Monster.ai", "16ed1e37d17804ed9818ab7c73a07ac7", "4fbe4d914ef1215736d542073e376103"),
}
GS_FOLDERS = stack_layout.GS_FOLDERS   # было ["GameServer", "Indun_GameServer"] (26.10: + Ch2_GameServer)
SUFFIX = ".bak_20261026_p91"
SRV_BACKUP = V2 + r"\_backup\2026-10-26_p91"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-26_exprate/server/v2"
LOG = os.path.join(HERE, "run_p91_20261026_deploy", "deploy.log")
BUSY = [r"GameServer\GameServer.exe", r"Indun_GameServer\GameServer.exe", r"NpcServer\NpcServer.exe", r"Indun_NpcServer\NpcServer.exe",
        r"GameServer\AsdaPatch.dll", r"Indun_GameServer\AsdaPatch.dll"]
AI = stack_layout.expand_paths(AI)        # 26.10: + Ch2_NpcServer / Ch2_GameServer (значения поля — копия побайтная)
BUSY = stack_layout.expand_list(BUSY)


def log(lines, line):
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-26_p91 и локально; существующие не перезаписываются."""
    src = V2 + "\\" + rel
    want = rmd5(src)
    for dst in (src + SUFFIX, SRV_BACKUP + "\\" + rel):
        have = rmd5(dst)
        if have == "none":
            rcopy(src, dst)
            have = rmd5(dst)
            if have != want:
                raise RuntimeError("бэкап %s не сошёлся (%s ≠ %s)" % (dst, have, want))
            log(lines, "  бэкап: %s %s" % (dst, want))
        elif have != want:
            raise RuntimeError("бэкап %s уже есть и это ДРУГОЙ файл (%s ≠ %s) — разберись вручную" % (dst, have, want))
    loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
    if os.path.exists(loc):
        if md5(loc) != want:
            raise RuntimeError("локальный бэкап %s уже есть и это ДРУГОЙ файл" % loc)
        return
    data = rread(src)
    if hashlib.md5(data).hexdigest() != want:
        raise RuntimeError("прочитанное по SSH %s не сошлось по md5" % src)
    os.makedirs(os.path.dirname(loc), exist_ok=True)
    with open(loc, "wb") as f:
        f.write(data)
    if md5(loc) != want:
        raise RuntimeError("локальный бэкап %s не сошёлся" % loc)
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".p91_upload"
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


def decode_log(raw):
    """Журнал патчей: AddonNPC пишет UTF-8, AsdaPatch (GameServer) — cp1251. ★ 26.10: прежняя проверка «есть байт D0 → UTF-8»
    ошибалась на cp1251 (D0 = «Р»), и строка «P91: потолок» не находилась (ложная тревога). Теперь строгий UTF-8, иначе cp1251."""
    if raw[:3] == b"\xef\xbb\xbf":
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", "replace")


def check_started(lines):
    """После старта: PatchLog GameServer/Indun/Ch2, блок последнего запуска — «[OK] P91_ExpCapRate», строка «P91: потолок», без провалов
    (patchlog); AI-файлы = новые. Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, ["P91_ExpCapRate"], ["P91: потолок"], log=lambda s: log(lines, s))
        good = good and ok
    for rel, (local, base, new) in AI.items():
        got = rmd5(V2 + "\\" + rel)
        log(lines, "%s: %s %s" % (rel, got, "новый" if got == new else "НЕ новый!"))
        good = good and got == new
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_p91 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                       "ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"))
    if "--check-started" in sys.argv:
        try:
            rc = check_started(lines)
        except Exception as e:
            log(lines, "ОШИБКА: %s" % e)
            rc = 7
        flush(lines)
        return rc
    try:
        busy = [rel for rel in BUSY if rbusy(V2 + "\\" + rel) == "BUSY"]
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or rollback):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")

        if rollback:
            todo = []
            for d in GS_FOLDERS:
                rel = d + r"\AsdaPatch.dll"
                if rmd5(V2 + "\\" + rel) == WANT_DLL:
                    todo.append((rel, set(PREV_DLL)))
            for rel, (local, base, new) in AI.items():
                if rmd5(V2 + "\\" + rel) == new:
                    todo.append((rel, {base}))
            if not todo:
                log(lines, "СТОП: на стойке нет файлов P91 — откатывать нечего")
                flush(lines)
                return 9
            for rel, allowed in todo:
                bak = rmd5(V2 + "\\" + rel + SUFFIX)
                if bak not in allowed:
                    log(lines, "СТОП: %s%s нет или это не прежний файл (%s)" % (rel, SUFFIX, bak))
                    flush(lines)
                    return 6
            for rel, allowed in todo:
                rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
                got = rmd5(V2 + "\\" + rel)
                log(lines, "%s: возвращён %s %s" % (rel, got, "OK" if got in allowed else "НЕ СОШЛОСЬ"))
                if got not in allowed:
                    flush(lines)
                    return 4
            log(lines, "ОТКАТ ГОТОВ (секция [P91_ExpCapRate] в ini останется и будет проигнорирована). Нужен старт стойки.")
            flush(lines)
            return 0

        if md5(BUILT_DLL) != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, md5(BUILT_DLL), WANT_DLL))
            flush(lines)
            return 3
        for rel, (local, base, new) in AI.items():
            lp = os.path.join(DATA, local)
            if not os.path.exists(lp) or md5(lp) != new:
                log(lines, "СТОП: %s нет или md5 не %s (перегенерировать: p91_monster_exp.py apply)" % (lp, new))
                flush(lines)
                return 3
        plan = []
        for d in GS_FOLDERS:
            exe = rmd5(V2 + "\\" + d + r"\GameServer.exe")
            cur = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
            log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (P91)" % (d, exe, cur, PREV_DLL.get(cur, "НЕ из допустимых" if cur != WANT_DLL else "уже P91"), WANT_DLL))
            if exe != GS_EXE:
                log(lines, "СТОП: GameServer.exe в %s = %s, а площадки P91 сверены по %s" % (d, exe, GS_EXE))
                flush(lines)
                return 8
            if cur == WANT_DLL:
                continue
            if cur not in PREV_DLL:
                log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
                flush(lines)
                return 8
            plan.append((d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL))
        for rel, (local, base, new) in AI.items():
            cur = rmd5(V2 + "\\" + rel)
            log(lines, "%s: сейчас %s → %s" % (rel, cur, "уже новый" if cur == new else new))
            if cur == new:
                continue
            if cur != base:
                log(lines, "СТОП: %s = %s, ожидалась база %s (данные менялись после разбора) — ничего не трогаю" % (rel, cur, base))
                flush(lines)
                return 8
            plan.append((rel, os.path.join(DATA, local), new))
        if not plan:
            log(lines, "СТОП: всё уже выложено")
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (%d файлов)" % len(plan))
            flush(lines)
            return 0
        for d in GS_FOLDERS:
            backup_one(d + r"\ConfigSet\patches.ini", lines)
        for rel, local, want in plan:
            backup_one(rel, lines)
            put(rel, local, want, lines)
        log(lines, "ГОТОВО: P91 (AsdaPatch %s) и Monster.ai (45 записей опыта) выложены. Старт стойки — за координатором; в PatchLog "
                   "GameServer/Indun — «[OK] P91_ExpCapRate» и «P91: потолок опыта за моба = уровень × max(1, fEvent + LuckyHours) / 9»; "
                   "затем python deploy_p91.py --check-started." % WANT_DLL)
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
