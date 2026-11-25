# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_l08.py — ВЫКЛАДКА / ОТКАТ L08_ListenArrayLeak (LoginPatch.dll, 27.10.2026): утечка массива подключений LoginManager
#   (окно 1098 «The connection to the server was lost due to an unstable network» при входе = 4101 код 1 из пинг-сторожа).
#   LoginPatch.dll в LoginManager (один на стойке, stack_layout): живая 55106cd6 (L01…L07) → WANT_DLL (+ L08). Секцию
#   [L08_ListenArrayLeak] (Enabled=1, ReuseSlot=1, EarlyClear=1, Sweep=1, LogPerMinute=30) и Version=9 DLL дописывает в
#   ConfigSet\patches.ini сама при первом старте (бережное слияние: значения администратора, в т.ч. L07 AllowLegacy=0, не трогаются).
#   Отчёт: Reports/loginmanager_l08/L08_REPORT.md; стенд LoginPatch/tools/stand_l08; регресс LoginPatch/tools/regress_all.bat.
#   ★ Выкладка и рестарт:
#     python restart_stack.py --deploy deploy_l08.py --expect L08_ListenArrayLeak
#   (restart_stack: объявление, 3 мин, остановка, этот скрипт с --apply, start.bat, проверка PatchLog LoginManager).
#   После старта (только чтение): python deploy_l08.py --check-started
#   Через час-другой работы (только чтение): python deploy_l08.py --check-leak — баланс SetEmpty/Clear в LoginoutCheck_<дата>.
#
# Выкладка (--apply; только при ОСТАНОВЛЕННОЙ стойке):
#   1. md5 собранной DLL = WANT_DLL; LoginManager.exe = LM_EXE (51db86b2, площадки сверены по нему стендом stand_l08).
#   2. Файлы не заняты процессами (занят — код 2).
#   3. LoginPatch.dll = PREV_DLL (или уже WANT — СТОП «уже выложено»). Иначе — СТОП, код 8, ничего не тронуто.
#   4. Бэкапы: DLL и patches.ini — рядом <файл>.bak_20261027_l08, в v2\_backup\2026-10-27_l08\… и локально
#      @@ASTORY_DEV_ROOT@@\_backup\2026-10-27_l08\server\v2\…
#   5. Заливка DLL (scp во временный файл, md5, копия поверх, сверка).
# Откат (--rollback; при остановленной стойке): DLL из <файл>.bak_20261027_l08. Секция [L08_ListenArrayLeak] остаётся в ini —
#   DLL v8 её игнорирует и понижает Version до 8. Быстро без замены: [L08_ListenArrayLeak] Enabled=0 + рестарт LoginManager.
# По умолчанию — сухой прогон (только чтение по SSH). Журнал: tools/run_l08_20261027_deploy/deploy.log (дописывается).
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки: LoginManager один (EXPECT["LoginManager"] == 1)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH (без побочных эффектов)
from deploy_p91 import decode_log
from deploy_p94 import log   # строка в консоль и в накопитель журнала (backup_one у p94 со своими путями — здесь свой)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
LM = "LoginManager"
BUILT_DLL = "@@ASTORY_DEV_ROOT_FWD@@/AstoryServer/Patches/LoginPatch/out/LoginPatch.dll"
WANT_DLL = "1bff1b631329d7e1c2347b3782d33eac"                    # LoginPatch L01…L07 + L08 (Config v9)
PREV_DLL = {"55106cd6b38678f97ce7f36389bdf8aa": "LoginPatch L01…L07 (живая на 27.10 01:00)"}
LM_EXE = "51db86b2a1c44b91b11bebfc343e88be"                     # LoginManager.exe с импортом LoginPatch.dll (= out\LoginManager.exe.loginpatch.exe)
SUFFIX = ".bak_20261027_l08"
SRV_BACKUP = V2 + r"\_backup\2026-10-27_l08"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-10-27_l08/server/v2"
LOG = os.path.join(HERE, "run_l08_20261027_deploy", "deploy.log")
BUSY = [LM + r"\LoginManager.exe", LM + r"\LoginPatch.dll"]
EXPECT_OK = ["L01_LoginLogMask", "L03_LoginSqlRefuse", "L02_LoginSqlLogMask", "L04_LoginIdentity", "L05_LogoutMd5Len",
             "L06_LoginMac", "L07_TrafficEncryption", "L08_ListenArrayLeak"]   # живой ini: все Enabled=1 (L07 AllowLegacy=0)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-10-27_l08 и локально; существующие не перезаписываются (сверка md5)."""
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
    import hashlib
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
    up = dst + ".l08_upload"
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


def latest(folder, mask):
    """Полный путь самого свежего файла по маске в папке стойки ('' — нет)."""
    rc, out = ps("$p = Get-ChildItem -LiteralPath %s -Filter %s -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | "
                 "Select-Object -First 1; if (-not $p) { Write-Output 'NOLOG'; return }; Write-Output $p.FullName" % (q(folder), q(mask)), timeout=120)
    path = out.splitlines()[-1].strip() if out else ""
    return "" if rc != 0 or path in ("", "NOLOG") else path


def check_started(lines):
    """После старта: PatchLog LoginManager, блок последнего запуска — [OK] у L01…L08, итог «ошибок 0», строка установки L08, без
    провалов (patchlog); md5 DLL. Только чтение."""
    # ★ 31.10.2026 (fix-check-started): разбор — patchlog.check_folder (блок ПОСЛЕДНЕГО запуска, «=== итог», PID работающего
    #   процесса); прежний поиск «[OK]» в хвосте суточного журнала видел [OK] прежнего старта того же дня.
    import dll_builds
    import patchlog
    ok, _ = patchlog.check_folder(LM, EXPECT_OK, ["L08: ProcConnect->SetEmpty"], log=lambda s: log(lines, s))
    got = rmd5(V2 + "\\" + LM + r"\LoginPatch.dll")
    # ★ 31.10.2026: более поздняя сборка цепочки LoginPatch (dll_builds) при подтверждённом журнале — не провал
    good = dll_builds.accept("LoginPatch", got, WANT_DLL, ok, "  LoginPatch.dll", lambda s: log(lines, s)) and ok
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("L08 стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def check_leak(lines):
    """Журнал стока LoginoutCheck_<сегодня>: баланс SetEmpty ↔ успешных Clear, «failed 1», последний CurrentUserCount; строки L08
    за сегодня из PatchLog. Только чтение."""
    day = time.strftime("%Y%m%d")
    path = V2 + "\\" + LM + r"\Log\LoginMngError\LoginoutCheck_%s.txt" % day
    if rmd5(path) == "none":
        log(lines, "нет %s" % path)
        return 5
    txt = decode_log(rread(path)).splitlines()
    adds = sum(1 for l in txt if "SetEmpty_ListenArray() : CurrentUserCount" in l)
    clears = [l for l in txt if "ClearListenArrayIndex() : CurrentUserCount" in l]
    failed = sum(1 for l in txt if "ClearListenArrayIndex() failed" in l)
    kicks = sum(1 for l in txt if "Disconnect_PingCount()" in l)
    last = [l for l in txt if "CurrentUserCount" in l]
    cnt = re.search(r"CurrentUserCount (-?\d+)", last[-1]).group(1) if last else "?"
    conn = [l for l in txt if " Connect : TotalConnect" in l or " Disconnect : TotalConnect" in l]
    m = re.search(r"TotalConnect (\d+), TotalDisconnect (\d+)", conn[-1]) if conn else None
    live = int(m.group(1)) - int(m.group(2)) if m else None
    log(lines, "%s: SetEmpty %d, успешных Clear %d, «failed» %d, пинг-киков %d; последний CurrentUserCount %s; живых по стоку %s" % (
        os.path.basename(path), adds, len(clears), failed, kicks, cnt, live if live is not None else "?"))
    log(lines, "  (журнал за весь день: до выкладки L08 баланс мог уже разойтись; сравнивать прирост после старта)")
    plog = latest(V2 + "\\" + LM + r"\Log\Log_Patch", "PatchLog_*.txt")
    if plog:
        ev = [l.strip() for l in decode_log(rread(plog)).splitlines() if "    L08: " in l and "ProcConnect->SetEmpty" not in l]
        log(lines, "  событий L08 в %s: %d; последние:" % (os.path.basename(plog), len(ev)))
        for l in ev[-5:]:
            log(lines, "    " + l[:200])
    return 0


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started, --check-leak."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv
    lines = []
    mode = ("ОТКАТ" if rollback else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv
            else "ПРОВЕРКА УТЕЧКИ" if "--check-leak" in sys.argv else "сухой прогон")
    log(lines, "== deploy_l08 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
    if stack_layout.EXPECT.get("LoginManager") != 1:
        log(lines, "СТОП: stack_layout ждёт LoginManager ×%s — скрипт рассчитан на один" % stack_layout.EXPECT.get("LoginManager"))
        flush(lines)
        return 8
    if "--check-started" in sys.argv or "--check-leak" in sys.argv:
        try:
            rc = check_started(lines) if "--check-started" in sys.argv else check_leak(lines)
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
        rel = LM + r"\LoginPatch.dll"
        cur = rmd5(V2 + "\\" + rel)

        if rollback:
            if cur != WANT_DLL:
                log(lines, "СТОП: %s = %s — это не L08, откатывать нечего" % (rel, cur))
                flush(lines)
                return 6
            bak = rmd5(V2 + "\\" + rel + SUFFIX)
            if bak not in PREV_DLL:
                log(lines, "СТОП: %s%s нет или это не прежняя DLL (%s)" % (rel, SUFFIX, bak))
                flush(lines)
                return 6
            rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
            got = rmd5(V2 + "\\" + rel)
            log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
            if got not in PREV_DLL:
                flush(lines)
                return 4
            log(lines, "ОТКАТ ГОТОВ (секция [L08_ListenArrayLeak] в ini останется и будет проигнорирована). Нужен старт стойки.")
            flush(lines)
            return 0

        if md5(BUILT_DLL) != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, md5(BUILT_DLL), WANT_DLL))
            flush(lines)
            return 3
        exe = rmd5(V2 + "\\" + LM + r"\LoginManager.exe")
        ini = rmd5(V2 + "\\" + LM + r"\ConfigSet\patches.ini")
        log(lines, "%s: LoginManager.exe %s; LoginPatch.dll сейчас %s (%s) → %s (L08); patches.ini %s" % (
            LM, exe, cur, PREV_DLL.get(cur, "уже L08" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL, ini))
        if exe != LM_EXE:
            log(lines, "СТОП: LoginManager.exe = %s, а площадки L08 сверены по %s" % (exe, LM_EXE))
            flush(lines)
            return 8
        if ini == "none":
            log(lines, "СТОП: нет ConfigSet\\patches.ini — DLL создала бы новый с MasterEnable=0 (все патчи выключены)")
            flush(lines)
            return 8
        if cur == WANT_DLL:
            log(lines, "СТОП: L08 уже выложен")
            flush(lines)
            return 8
        if cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та LoginPatch.dll (%s) — ничего не затираю" % (LM, cur))
            flush(lines)
            return 8
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (LoginManager: LoginPatch.dll %s → %s)" % (cur, WANT_DLL))
            flush(lines)
            return 0
        backup_one(LM + r"\ConfigSet\patches.ini", lines)
        backup_one(rel, lines)
        put(rel, BUILT_DLL, WANT_DLL, lines)
        log(lines, "ГОТОВО: L08 (LoginPatch %s) в %s. Дальше restart_stack: start.bat; в PatchLog LoginManager — «[OK] L08_ListenArrayLeak»; "
                   "затем python deploy_l08.py --check-started." % (WANT_DLL, LM))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
