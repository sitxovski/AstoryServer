# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p127b.py — ВЫКЛАДКА / ОТКАТ AsdaPatch v81 = v80 (P127 после ревизии 24, живая с 18.11 21:26) + P127 А2.2 «живые правки»
#   (probe, exp — опыт/уровень событием стока через P75, title_add / title_del — через AddFameBit и P24, fame_recalc — P25, notice — 3113
#   одному игроку). 18.11.2026. Документ: AstoryServer/Docs/GameServer/admin-bridge-p127.md (А2.2); отчёт impl_bridge_p127.md (раздел А2.2).
#   Образец — deploy_p127.py. Меняется ТОЛЬКО AsdaPatch.dll во всех 3 папках GameServer: секция [P127_AdminBridge] (Enabled/Mode) и файл
#   секретов моста НЕ трогаются (Mode остаётся, каким его поставил координатор). SQL (новые op в adm.BridgeEnqueue) — deploy_admin_center.py.
#   Выкладка — с объявлением:
#     py -3.13 restart_stack.py --deploy deploy_p127b.py --expect P127_AdminBridge --expect P75_LevelUpPotion --expect P24_FameRatingRevoke --expect P25_GmRatingRecalc
#   После старта: py -3.13 deploy_p127b.py --check-started (PatchLog, md5, пульс трёх узлов с ver 81).
#   ОТКАТ: --rollback (или ASDA_P127B_ROLLBACK=1 + --apply) — DLL <- v80 d1581b14 (бэкап рядом); панель сама уйдёт на «кик + запись» (ver 80).
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, rmd5, rbusy, rread, rcopy, rupload, rdel, md5   # общие функции SSH

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
BUILT_DLL = os.path.join(HERE, "p127_data", "AsdaPatch_v81p127b_98e18599.dll")   # закреплённая сборка: out\ перепишет следующая
WANT_DLL = "98e185997eaececb109e90f6cd4e1b50"                       # AsdaPatch v81 = v80 + P127 А2.2 (после ревизии 25)
PREV_DLL = {"d1581b14dd8d9b0fc0643f0c567e4eae": "AsdaPatch v80 + P127 после ревизии 24 (живая с 18.11 21:26, tools/p127_data)"}
SERVICE_SECRETS = r"@@ASTORY_SERVER_ROOT@@\AdminCenter\secrets\asda_admin.ini"     # файл секретов админ-центра (core/config.SECRET_FILE)
BRIDGE_SECRET_REL = r"ConfigSet\admin_bridge.ini"                  # [P127_AdminBridge] SecretFile (умолчание)
INI_REL = r"ConfigSet\patches.ini"
SECTION = "P127_AdminBridge"
INI_KEYS = ["Enabled", "Mode", "PollMs", "KickType", "SecretFile"]
OTHER_SECTIONS = ["P21_TitleMask512", "P123_GmMapJump", "P73_EacBridge", "P47_IdentityOperatorGate", "P48_KickAutoBlock",
                  "P58_DisconnectReasonLog", "P61_TrafficEncryption", "P53_AcJournal", "P122_PetFuncFloor", "P121_CharRenameGuard",
                  "P118_AuctionTradeBlock", "P120_MineTravel", "P117_PlusPackOnce", "P75_LevelUpPotion", "P63_InFlightLock"]   # проверка старта
NEED_LINES = ["P127: мост админ-центра", "P127: живьём (v81)", "P21: предел FameInfo.txt 256", "P123: CharJumpCommandPosition @0x0054EF50",
              "P73: мост EAC"]                                       # строки установки, обязательны
INI_VERSION = 81                                                    # Config::kVersion сборки WANT_DLL
GS_EXE = "e7b4ac38e8328aaa847bbd9bf261bb01"                         # площадки сверены по нему (verify_p127, stand_p127)
GS_FOLDERS = stack_layout.GS_FOLDERS
SUFFIX = ".bak_20261118_p127b"
SRV_BACKUP = V2 + r"\_backup\2026-11-18_p127b"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-18_p127b/server/v2"
RUN_DIR = os.path.join(HERE, "run_p127b_20261118_deploy")
LOG = os.path.join(RUN_DIR, "deploy.log")
BUSY = [d + r"\GameServer.exe" for d in GS_FOLDERS] + [d + r"\AsdaPatch.dll" for d in GS_FOLDERS]


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def ini_state(folder):
    """Живой patches.ini папки (чтение по SSH): (md5, Version, есть ли секция, {ключ: значение} секции)."""
    data = rread(V2 + "\\" + folder + "\\" + INI_REL)
    text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("latin-1")
    ver, cur, keys, has = None, None, {}, False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip()
            has = has or cur == SECTION
            continue
        if not s or s.startswith(";") or "=" not in s:
            continue
        k, v = [x.strip() for x in s.split("=", 1)]
        if cur == "General" and k == "Version":
            ver = v
        elif cur == SECTION:
            keys[k] = v
    return hashlib.md5(data).hexdigest(), ver, has, keys


def service_secrets_ok():
    """Есть ли в файле секретов службы BRIDGE_PASSWORD и BRIDGE_HMAC_KEY (на сервере; значения не читаются сюда)."""
    rc, out = ps("$f=%s; if (-not (Test-Path -LiteralPath $f)) { 'NOFILE' } else { "
                 "$p = [bool](Select-String -LiteralPath $f -Pattern '^\\s*BRIDGE_PASSWORD\\s*=' -Quiet); "
                 "$k = [bool](Select-String -LiteralPath $f -Pattern '^\\s*BRIDGE_HMAC_KEY\\s*=\\s*[0-9a-fA-F]{64}\\s*$' -Quiet); "
                 "'P=' + $p + ' K=' + $k }" % q(SERVICE_SECRETS))
    line = out.splitlines()[-1] if out else ""
    return rc == 0 and line == "P=True K=True", line


def sql_login_ok():
    """Логин asda_bridge и процедуры моста есть (Windows-вход Administrator, только SELECT)."""
    rc, out = ps("$o = & sqlcmd -S lpc:.\\SQLEXPRESS -E -d AsdaAdmin -h -1 -W -Q \"SET NOCOUNT ON; SELECT CAST(COUNT(*) AS varchar) "
                 "FROM sys.server_principals WHERE name = N'asda_bridge'; SELECT CAST(COUNT(*) AS varchar) FROM sys.objects WHERE "
                 "schema_id = SCHEMA_ID('adm') AND type = 'P' AND name LIKE 'Bridge%%'\" 2>&1; ($o | Out-String).Trim()")
    vals = [x.strip() for x in out.splitlines() if x.strip().isdigit()]
    return rc == 0 and vals[:2] == ["1", "7"], " / ".join(vals) or out[-200:]


def write_bridge_secret(folder, lines):
    """ConfigSet\\admin_bridge.ini папки: [Bridge] Password, HmacKey из файла секретов службы — целиком НА СЕРВЕРЕ (в вывод — только md5)."""
    dst = V2 + "\\" + folder + "\\" + BRIDGE_SECRET_REL
    script = r"""
$src=%(src)s; $dst=%(dst)s
function Sec($key) { foreach ($l in Get-Content -LiteralPath $src -Encoding UTF8) { if ($l -match ('^\s*' + $key + '\s*=\s*(.+)$')) { return $Matches[1].Trim().Trim('"') } } throw "нет $key" }
$pw = Sec 'BRIDGE_PASSWORD'; $hk = Sec 'BRIDGE_HMAC_KEY'
$txt = "; секреты моста P127 (deploy_p127.py %(stamp)s): не копировать, не печатать`r`n[Bridge]`r`nPassword=$pw`r`nHmacKey=$hk`r`n"
# ревизия 24 К-8: сначала пустой временный файл с узкими правами, потом содержимое, потом замена — секрет ни мгновения не лежит
#   с правами папки
$tmp = $dst + '.p127tmp'
if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
[IO.File]::WriteAllText($tmp, '')
icacls $tmp /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' 'Administrator:R' | Out-Null
if ($LASTEXITCODE) { Remove-Item -LiteralPath $tmp -Force; throw "icacls $tmp" }
[IO.File]::WriteAllText($tmp, $txt, (New-Object Text.UnicodeEncoding($false, $true)))
Move-Item -LiteralPath $tmp -Destination $dst -Force
icacls $dst /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' 'Administrator:R' | Out-Null
if ($LASTEXITCODE) { throw "icacls $dst" }
Remove-Variable pw, hk, txt
'OK ' + (Md5Of $dst)
""" % {"src": q(SERVICE_SECRETS), "dst": q(dst), "stamp": time.strftime("%Y-%m-%d %H:%M")}
    rc, out = ps(script)
    last = out.splitlines()[-1] if out else ""
    if rc != 0 or not last.startswith("OK "):
        raise RuntimeError("файл секретов моста %s не записан: %s" % (dst, out[-300:]))
    log(lines, "  %s записан (md5 %s; права Administrators/SYSTEM/Administrator)" % (dst, last[3:]))


def seed_section(folder, has, keys, lines):
    """Секция [P127_AdminBridge] Enabled=1, Mode=0 в конец patches.ini (UTF-16LE), если её нет; остальные ключи DLL допишет сама."""
    if has:
        log(lines, "  секция [%s] уже есть: %s — не трогаю" % (SECTION, ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys) or "—"))
        return
    path = V2 + "\\" + folder + "\\" + INI_REL
    rc, out = ps("$p=%s; $t=\"`r`n[%s]`r`nEnabled=1`r`nMode=0`r`n\"; [IO.File]::AppendAllText($p, $t, [Text.Encoding]::Unicode); 'OK ' + (Md5Of $p)"
                 % (q(path), SECTION))
    if rc != 0 or "OK " not in out:
        raise RuntimeError("секция в %s не дописана: %s" % (path, out[-300:]))
    _, _, has2, k2 = ini_state(folder)
    if not has2 or k2.get("Enabled") != "1" or k2.get("Mode") != "0":
        raise RuntimeError("после дописывания секция [%s] в %s читается не так: %s" % (SECTION, path, k2))
    log(lines, "  [%s] Enabled=1, Mode=0 дописаны в %s (остальные ключи — DLL при старте)" % (SECTION, INI_REL))


def backup_one(rel, lines):
    """Бэкап файла стойки: рядом (SUFFIX), в v2\\_backup\\2026-11-18_p127 и локально; существующие не перезаписываются."""
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
    log(lines, "  локальный бэкап: %s %d б" % (loc, len(data)))


def put(rel, local, want, lines):
    """Залить local → v2\\rel через временный файл со сверкой md5."""
    dst = V2 + "\\" + rel
    up = dst + ".p127_upload"
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


def survey(lines):
    """Сверки по всем папкам и общим условиям (только чтение). → (план [(папка, есть секция, ключи)], стоп-код или 0)."""
    plan = []
    sok, sline = service_secrets_ok()
    log(lines, "секреты моста в файле службы %s: %s" % (SERVICE_SECRETS, "есть" if sok else "НЕТ (" + sline + ")"))
    if not sok:
        log(lines, "СТОП: сначала deploy_admin_center.py (шаг 4 допишет BRIDGE_PASSWORD и BRIDGE_HMAC_KEY, шаг 5 — SQL моста)")
        return plan, 8
    lok, lline = sql_login_ok()
    log(lines, "SQL: логин asda_bridge / процедур adm.Bridge*: %s" % lline)
    if not lok:
        log(lines, "СТОП: нет логина asda_bridge или не 7 процедур adm.Bridge* — сначала deploy_admin_center.py (adminc_07_bridge.sql)")
        return plan, 8
    for d in GS_FOLDERS:
        base = V2 + "\\" + d + "\\"
        exe = rmd5(base + "GameServer.exe")
        cur = rmd5(base + "AsdaPatch.dll")
        ini_md5, ver, has, keys = ini_state(d) if rmd5(base + INI_REL) != "none" else ("none", None, False, {})
        sec = rmd5(base + BRIDGE_SECRET_REL)
        log(lines, "%s: GameServer.exe %s; AsdaPatch сейчас %s (%s) → %s (v81); файл секретов моста %s" % (
            d, exe, cur, PREV_DLL.get(cur, "уже v81" if cur == WANT_DLL else "НЕ из допустимых"), WANT_DLL,
            "есть" if sec != "none" else "нет — будет записан"))
        if ini_md5 == "none":
            log(lines, "СТОП: в %s нет ConfigSet\\patches.ini — разберись вручную" % d)
            return plan, 8
        log(lines, "  patches.ini %s: Version %s → DLL поднимет до %d; секция [%s] %s" % (
            ini_md5, ver, INI_VERSION, SECTION,
            ("есть: " + ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)) if has
            else "нет — будет дописана Enabled=1, Mode=0"))
        if exe != GS_EXE:
            log(lines, "СТОП: GameServer.exe в %s = %s, а площадки v81 сверены по %s" % (d, exe, GS_EXE))
            return plan, 8
        if cur != WANT_DLL and cur not in PREV_DLL:
            log(lines, "СТОП: в %s не та AsdaPatch.dll (%s) — ничего не затираю" % (d, cur))
            return plan, 8
        plan.append((d, has, keys, cur != WANT_DLL))
    return plan, 0


def check_started(lines):
    """После старта: PatchLog каждого GameServer — «[OK]» P127 и соседей; DLL = WANT; пульс узлов в AsdaAdmin (только чтение)."""
    import dll_builds
    import patchlog
    good = True
    for d in GS_FOLDERS:
        ok, _ = patchlog.check_folder(d, [SECTION] + OTHER_SECTIONS, NEED_LINES, log=lambda s: log(lines, s))
        good = good and ok
        got = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll")
        good = dll_builds.accept("AsdaPatch", got, WANT_DLL, ok, d + r"\AsdaPatch.dll", lambda s: log(lines, s)) and good
    rc, out = ps("$o = & sqlcmd -S lpc:.\\SQLEXPRESS -E -d AsdaAdmin -h -1 -W -s '|' -Q \"SET NOCOUNT ON; SELECT node, mode, ver, "
                 "DATEDIFF(second, heartbeat, SYSUTCDATETIME()), present, errors FROM adm.bridge_node\" 2>&1; ($o | Out-String).Trim()")
    seen = {}
    for ln in out.splitlines():
        f = [x.strip() for x in ln.split("|")]
        if len(f) == 6 and f[3].lstrip("-").isdigit():
            seen[f[0]] = f
    for d in GS_FOLDERS:
        f = seen.get(d)
        fresh = bool(f) and int(f[3]) <= 15 and f[2] == str(INI_VERSION)
        log(lines, "%s: узел моста %s" % (d, ("пульс %s с, Mode=%s, v%s, в игре %s, ошибок SQL %s" % (f[3], f[1], f[2], f[4], f[5])) if f
                                          else "НЕТ строки в adm.bridge_node"))
        good = good and fresh
    log(lines, "ПРОВЕРКА СТАРТА: %s" % ("всё стоит" if good else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if good else 5


def rollback(lines):
    """Вернуть прежнюю DLL v80 из бэкапов рядом (только поверх WANT); секция и файл секретов остаются. → код возврата."""
    todo = [d for d in GS_FOLDERS if rmd5(V2 + "\\" + d + r"\AsdaPatch.dll") == WANT_DLL]
    for d in todo:
        bak = rmd5(V2 + "\\" + d + r"\AsdaPatch.dll" + SUFFIX)
        if bak not in PREV_DLL:
            log(lines, "СТОП: %s\\AsdaPatch.dll%s нет или это не прежняя DLL (%s)" % (d, SUFFIX, bak))
            return 6
    for d in todo:
        rel = d + r"\AsdaPatch.dll"
        rcopy(V2 + "\\" + rel + SUFFIX, V2 + "\\" + rel)
        got = rmd5(V2 + "\\" + rel)
        log(lines, "%s: возвращена %s %s" % (rel, got, "OK" if got in PREV_DLL else "НЕ СОШЛОСЬ"))
        if got not in PREV_DLL:
            return 4
    log(lines, "  файл секретов и секция [%s] остаются — их читает и v80" % SECTION)
    log(lines, "ГОТОВО: ОТКАТ (DLL %d папок; секция [%s] в ini останется и будет проигнорирована). Нужен старт стойки." % (len(todo), SECTION))
    return 0


def main():
    """Точка входа: сухой прогон, --apply, --rollback, --check-started."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    # ★ restart_stack зовёт скрипт только с --apply: ASDA_P127B_ROLLBACK=1 превращает этот вызов в откат (тот же один перезапуск).
    rb = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_P127B_ROLLBACK") == "1")
    apply = apply and not rb
    lines = []
    mode = "ОТКАТ" if rb else "ВЫКЛАДКА" if apply else "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else "сухой прогон"
    log(lines, "== deploy_p127b %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode))
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
        if busy and (apply or rb):
            log(lines, "СТОП: стойка не остановлена — ничего не тронуто")
            flush(lines)
            return 2
        if busy:
            log(lines, "  (сухой прогон: процессы работают — к выкладке стойку нужно остановить)")
        if rb:
            rc = rollback(lines)
            flush(lines)
            return rc
        built = md5(BUILT_DLL)
        if built != WANT_DLL:
            log(lines, "СТОП: собранная %s = %s, ожидалась %s" % (BUILT_DLL, built, WANT_DLL))
            flush(lines)
            return 3
        log(lines, "  собранная DLL %s — OK" % built)
        plan, stop = survey(lines)
        if stop:
            flush(lines)
            return stop
        if not apply:
            log(lines, "сухой прогон: всё готово к --apply (DLL — %d папок из %d; секция и файл секретов — без изменений)"
                % (sum(1 for p in plan if p[3]), len(plan)))
            flush(lines)
            return 0
        for d, has, keys, need_dll in plan:
            log(lines, "%s:" % d)
            if not has:
                raise RuntimeError("в %s нет секции [%s] — сначала deploy_p127.py" % (d, SECTION))
            if rmd5(V2 + "\\" + d + "\\" + BRIDGE_SECRET_REL) == "none":
                raise RuntimeError("в %s нет файла секретов моста — сначала deploy_p127.py" % d)
            backup_one(d + "\\" + INI_REL, lines)
            if need_dll:
                backup_one(d + r"\AsdaPatch.dll", lines)
                put(d + r"\AsdaPatch.dll", BUILT_DLL, WANT_DLL, lines)
            log(lines, "  секция [%s] и секреты — без изменений (%s)" % (SECTION, ", ".join("%s=%s" % (k, keys[k]) for k in INI_KEYS if k in keys)))
        log(lines, "ГОТОВО: v81 (AsdaPatch %s) — %d папок; Mode не менялся. Дальше restart_stack: start.bat; затем "
                   "py -3.13 deploy_p127b.py --check-started." % (WANT_DLL, len(plan)))
    except Exception as e:
        log(lines, "ОШИБКА: %s" % e)
        flush(lines)
        return 7
    flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
