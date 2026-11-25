# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# restart_stack.py — перезапуск dev-стойки с выкладкой (общий; первая версия — restart_stack_p76.py; слово владельца 21.10.2026: «можешь сам перезапускать сервера,
# полной стойкой; перед перезапуском — сообщение ботом в канал testing-info всем @BetaTester на EN/AR/RU, что сервер будет
# перезапущен через 3 минуты; отсчитать 3 минуты и перезапустить»).
#
# Шаги (каждый — с проверкой; провал → стоп с кодом, дальше не идёт):
#   1. Объявление: AstoryAdminCenter/DiscordBot/announce_restart.py (канал test-info, роль Beta Tester, EN/AR/RU, 3 минуты).
#   2. Ожидание 180 с.
#   3а. ★ 07.11 (баг 9): штатное завершение GameServer (SC_CLOSE окнам через задачу /IT): игроки сохраняются; --no-graceful-stop — пропустить.
#   3. Остановка стойки: taskkill /f 9 видов процессов (как stop_servers.bat / start.bat) + node gp7-server; проверка, что их нет.
#   4. Выкладка: --deploy <скрипт>.py (зовётся с --apply; ждём «ГОТОВО» в выводе) — бэкапы и сверка md5 в самом скрипте.
#   4б2. ★ 05.11 (dungeon-relog, P108): EXEC dbo.UP_AsdaDungeonRelogReset — точки входа данжей в CharPos (до 4в; нет процедуры — пропуск;
#        выключить — --skip-dungeon-relog-reset).
#   4в. ★ 26.10 (charpos): сброс устаревших строк dbo.CharPos/Us_member — EXEC dbo.UP_AsdaCharPosReset при остановленной стойке.
#   5. Запуск: start.bat одноразовой задачей планировщика /RU Administrator /IT (интерактивная сессия администратора), задача удаляется.
#   0.  ★ 26.10 (канал 2; инцидент 18:55): паритет копий Ch2_* с полем ДО объявления и остановки — расхождение →
#       стойка не тронута, объявления нет (код 6). --skip-parity — пропустить (только осознанно).
#   4б. после выкладки — stack_parity.py --sync (расходящееся берётся с поля); старт блокирует только СУЩЕСТВЕННОЕ
#       расхождение (exe/dll/patches.ini, код 6), прочее — предупреждение. Файлы, которые серверы пишут во время работы
#       (EventLog.txt, *.log, …), не сверяются. Состав стойки — stack_layout.py (единый список папок).
#   6. Проверка: 15 процессов поднялись; в PatchLog каждого GameServer (stack_layout.GS_FOLDERS) — «[OK] <патч>» для каждого
#      --expect, MISMATCH 0, и у копий Ch2_* столько же [OK], сколько у поля. ★ 31.10: разбор — patchlog.check_folder (блок
#      последнего запуска, «=== итог», провалы, PID работающего процесса).
# Запуск: python restart_stack.py --deploy deploy_xxx.py --expect P29_LevelCap [--expect ...] [--no-announce] [--wait 180]
# ★ 19.11.2026 (админ-центр А3, ревизия 31 Н-В2): --start-only — ТОЛЬКО запуск стойки, которая уже целиком остановлена (после
#   объявленной остановки, сорвавшейся на выкладке). Ни объявления, ни остановки, ни выкладки, ни предпроверки паритета (после
#   остановки и так идёт stack_parity --sync, шаг 4б). Если хоть один процесс стойки работает — СТОП, код 7: ничего не запускает и
#   не останавливает (тихого рестарта с игроками не бывает).
# ★ 20.11.2026 (админ-центр А5.1): --stop-only — объявленная ОСТАНОВКА без запуска (обслуживание): объявление Discord (--kind stop),
#   ожидание, штатное завершение GameServer, остановка, проверка «процессов 0». Ни выкладки, ни паритета, ни брандмауэра (они для
#   старта), ни сброса CharPos (его делает следующий --start-only перед стартом). Несовместим с --deploy и --start-only (код 1).
# ★ 20.11.2026 (А5.1): отсчёт в игре — если задана переменная ASDA_RESTART_TICK (JSON-список argv), шаг 2 зовёт эту команду
#   с добавленным числом оставшихся секунд: сразу после объявления, затем каждую минуту и за 30 с (панель шлёт объявление в игру
#   мостом P127). Сбой команды — только предупреждение; общая длина ожидания та же (--wait). Без переменной — прежний time.sleep.
# ★ 20.11.2026 (ревизия 41): ОДИН restart_stack.py на ПК за раз — файл-замок _restart_stack.lock рядом со скриптом; второй запуск —
#   код 8, ничего не делается (В-1). Счёт процессов, который не прочитан (сбой SSH), больше не считается «всё остановлено» (Н-4).
#   --help / -h — эта шапка, без действий.
# ★ 24.11.2026 (админ-центр А7.5, ревизия 77 В-2): ОТМЕТКА «ИДЁТ УПРАВЛЕНИЕ СТОЙКОЙ» для уведомлений владельцу — файл ACTIVITY_FILE на
#   сервере (по SSH, время — по часам сервера): при старте «phase=run until=старт+45 мин» (предельный срок на случай падения скрипта),
#   по завершении — «phase=done until=конец+15 мин» (стойка поднимается после рестарта), после --stop-only с кодом 0 — «phase=stopped
#   until=конец+12 ч» (штатная остановка). Служба панели (domains/notify.py) до срока не шлёт «стойка не поднялась» и «EacServer не
#   работает». Сбой записи отметки — только предупреждение: рестарт она не останавливает.
#   ★ ревизия 78: первая отметка — внутри try (Ctrl+C во время неё — тоже «done» и снятый замок, К-1); код 1 (ключи) и 7 (--start-only /
#   --stop-only отказал, стойка не тронута) возвращают ПРЕЖНЮЮ отметку (К-2: холостой запуск не снимает «stopped» владельца).
import json
import os
import subprocess
import sys
import time

SSH = ["ssh", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", "Administrator@@@ASTORY_SERVER_VPN_IP@@"]
V2_LOCAL = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
V2_SHARE = "//@@ASTORY_SERVER_HOSTNAME@@/h(@@ASTORY_SERVER_HOSTNAME@@_ns)/ASDA/Working_ASDA/v2"
BOT = r"@@ASTORY_DEV_ROOT@@\AstoryAdminCenter\DiscordBot"
TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
from stack_layout import PROCS, EXPECT, TOTAL_PROCS, GS_FOLDERS, TWINS, CRITICAL_FILES   # ★ 26.10: единый состав стойки (канал 2)

# ★ 26.10.2026: --single-channel — стойка БЕЗ канала 2 (после deploy_channel2_rollback.py): 12 процессов, без Ch2_*.
if "--single-channel" in sys.argv:
    GS_FOLDERS = [d for d in GS_FOLDERS if d not in TWINS]
    EXPECT = dict(EXPECT, RelayServer=EXPECT["RelayServer"] - 1, NpcServer=EXPECT["NpcServer"] - 1, GameServer=EXPECT["GameServer"] - 1)
    CRITICAL_FILES = [f for f in CRITICAL_FILES if f.split("\\")[0] not in TWINS]
    TWINS = {}


def say(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def ssh_ps(cmd, timeout=180):
    """PowerShell-команда на сервере; возврат (код, вывод)."""
    p = subprocess.run(SSH + ["powershell -NoProfile -Command \"%s\"" % cmd.replace('"', '\\"')],
                       capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode("cp866", "replace") + p.stderr.decode("cp866", "replace")


# ★ 07.11.2026 (баг 9, игрок Player58: «после рестарта в случайной точке карты»). GameServer пишет позицию только при выходе/обрыве
#   (DisConnectUser → 2003) и при портале (2091 — СТАРАЯ карта и её клетка; UPUserNumUp меняет только Poridx). Stop-Process -Force
#   не сохраняет никого: кто сменил карту за сессию, входит на новую карту с клеткой прежней (Zeus 04.11: Sillaris (126,89) — клетка
#   Sunny Coast; Player56 02.11: Flammio (157,357) — клетка Alpen). Штатный путь оригинала — закрытие окна: WM_SYSCOMMAND SC_CLOSE →
#   DialogFunc → sub_4A5720 → разрушение карт → sub_4BFBE0 → Send_AllDisConnectUser → DisConnectUser каждому. Окна GS живут в
#   интерактивной сессии, поэтому сообщение шлёт одноразовая задача /IT (как запуск start.bat). Шаг — до Stop-Process, который
#   остаётся страховкой: зависший GS будет снят как раньше. --no-graceful-stop — выключить.
GRACEFUL_GS_SEC = 90      # предел ожидания выхода GameServer после SC_CLOSE
GRACEFUL_DB_SEC = 30      # предел ожидания записи выходов в БД (DBManager исполняет очередь после выхода GS)
GRACEFUL_DB_TAIL_SEC = 5  # запас DBManager: Relay при разрыве с GS сам чистит Usernum (UpGameServerStart) — ноль ещё не значит «очередь пуста»
GRACEFUL_TASK = "AsdaStackClose_coord"              # одноразовая задача планировщика
GRACEFUL_PS1 = V2_LOCAL + r"\_stack_close.ps1"      # сценарий на сервере (удаляется после шага)
GRACEFUL_SCRIPT = r"""# _stack_close.ps1 - SC_CLOSE every GameServer dialog (restart_stack.py, step 3a). ASCII only.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class StackClose {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    public static int Close(HashSet<uint> pids) {
        int n = 0;
        EnumWindows((h, l) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            StringBuilder c = new StringBuilder(64); GetClassName(h, c, 64);
            if (pids.Contains(pid) && c.ToString() == "#32770" && PostMessage(h, 0x112, (IntPtr)0xF060, IntPtr.Zero)) { n++; }
            return true; }, IntPtr.Zero);
        return n;
    }
}
'@
$pids = New-Object 'System.Collections.Generic.HashSet[uint32]'
Get-Process -Name GameServer -ErrorAction SilentlyContinue | ForEach-Object { [void]$pids.Add([uint32]$_.Id) }
$n = [StackClose]::Close($pids)
Set-Content -Path ($PSCommandPath + '.result') -Value ('processes=' + $pids.Count + ' windows=' + $n)
"""


def graceful_stop():
    """Штатное завершение GameServer перед Stop-Process: SC_CLOSE всем окнам, ожидание выхода процессов и записи выходов в БД.
    Любой сбой — только предупреждение: следующий шаг снимет процессы как раньше. → (выход GS дождались, остаток «в игре» или None)."""
    import base64
    data = base64.b64encode(GRACEFUL_SCRIPT.encode("ascii")).decode("ascii")
    rc, out = ssh_ps("[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String('%s')); "
                     "Remove-Item '%s.result' -ErrorAction SilentlyContinue; "
                     "schtasks /Create /F /TN %s /SC ONCE /ST 23:59 /RU Administrator /IT /TR 'powershell -NoProfile -ExecutionPolicy Bypass "
                     "-WindowStyle Hidden -File %s'; schtasks /Run /TN %s" % (GRACEFUL_PS1, data, GRACEFUL_PS1, GRACEFUL_TASK, GRACEFUL_PS1, GRACEFUL_TASK))
    say("   задача SC_CLOSE: код %d" % rc)
    left, closed = None, False
    t0 = time.time()
    res = ""                                          # итог сценария закрытия
    try:
        while time.time() - t0 < GRACEFUL_GS_SEC:
            rc, out = ssh_ps("@(Get-Process GameServer -ErrorAction SilentlyContinue).Count")
            left = next((int(l) for l in out.split() if l.isdigit()), None)
            if left == 0:
                closed = True
                break
            time.sleep(3)
    finally:
        rc, res = ssh_ps("Get-Content '%s.result' -ErrorAction SilentlyContinue; schtasks /Delete /F /TN %s | Out-Null; "
                         "Remove-Item '%s','%s.result' -ErrorAction SilentlyContinue" % (GRACEFUL_PS1, GRACEFUL_TASK, GRACEFUL_PS1, GRACEFUL_PS1))
    say("   сценарий: %s; GameServer вышли: %s за %d с (осталось %s)" % (
        next((l.strip() for l in res.splitlines() if "windows=" in l), "итога нет"), "да" if closed else "НЕТ", time.time() - t0, left))
    ingame = None
    t0 = time.time()
    while closed and time.time() - t0 < GRACEFUL_DB_SEC:
        rc, out = ssh_ps(r"& sqlcmd -S localhost\SQLEXPRESS -E -d Joy1 -b -h -1 -W -Q 'SET NOCOUNT ON; SELECT COUNT(*) FROM dbo.CharPos WHERE Usernum <> -1'")
        ingame = next((int(l) for l in out.split() if l.isdigit()), None)
        if ingame == 0:
            break
        time.sleep(3)
    say("   в игре по CharPos после выхода GS: %s" % ("не проверялось" if ingame is None else ingame))
    if closed:
        time.sleep(GRACEFUL_DB_TAIL_SEC)
    return closed, ingame


COUNTS_MARK = "COUNTS_OK"   # ★ 20.11.2026 (ревизия 41 Н-4): метка «счёт прочитан» в выводе counts()


def counts():
    """{процесс: число} работающих процессов стойки; None — НЕ ПРОЧИТАНО (сбой SSH, код ≠ 0, нет метки). ★ ревизия 41 Н-4: прежде
    сбой SSH давал {} — «всё остановлено», и рестарт шёл дальше к CharPos и start.bat при живых процессах."""
    names = ",".join(PROCS)
    rc, out = ssh_ps("Get-Process %s -ErrorAction SilentlyContinue | Group-Object ProcessName | ForEach-Object { $_.Name + '=' + $_.Count }; "
                     "Write-Output '%s'" % (names, COUNTS_MARK))
    if rc != 0 or COUNTS_MARK not in out:
        return None
    res = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.strip().split("=", 1)
            if v.isdigit():
                res[k] = int(v)
    return res


def firewall_missing():
    """★ 26.10.2026: exe стойки (stack_layout.FIREWALL_EXES) без входящего правила Allow TCP (включено, профиль с Private)
    в брандмауэре Windows сервера. Возврат (список путей без правила | None — проверка не удалась). Только чтение."""
    from stack_parity import run_ps
    from stack_layout import FIREWALL_EXES
    script = (
        "$want = @(" + ",".join("'%s'" % (V2_LOCAL + "\\" + e).lower() for e in FIREWALL_EXES) + ")\n"
        "$have = @{}\n"
        "foreach ($r in (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)) {\n"
        "  if (($r.Profile.ToString() -notmatch 'Private|Any')) { continue }\n"
        "  $app = ($r | Get-NetFirewallApplicationFilter).Program; if (-not $app) { continue }\n"
        "  $pf = $r | Get-NetFirewallPortFilter; if ($pf.Protocol -notin @('TCP','Any')) { continue }\n"
        "  $have[$app.ToLower()] = 1 }\n"
        "foreach ($w in $want) { if (-not $have.ContainsKey($w)) { Write-Output ('FWMISS|' + $w) } }\n"
        "Write-Output 'FWEND'\n")
    try:
        rc, out, err = run_ps(script, timeout=180)
    except subprocess.TimeoutExpired:
        return None
    if "FWEND" not in out:
        return None
    return [l.split("|", 1)[1].strip() for l in out.splitlines() if l.startswith("FWMISS|")]


def critical_sizes():
    """★ 26.10.2026: размеры ВСЕХ критичных файлов стойки (stack_layout.CRITICAL_FILES: 12 общих ini/bat, patches.ini каждого
    GameServer и NpcServer, поканальные файлы Ch2_*) по SSH — {путь: байты | 'NONE'}; пусто — SSH не ответил.
    Скрипт уходит файлом (stack_parity.run_ps): список длинный для -EncodedCommand. Только чтение (Test-Path / Get-Item)."""
    from stack_parity import run_ps
    script = ("$v2 = '" + V2_LOCAL + "'\n"
              "foreach ($r in @(" + ",".join("'%s'" % f for f in CRITICAL_FILES) + ")) { $p = Join-Path $v2 $r; "
              "if (Test-Path -LiteralPath $p) { Write-Output ('CF|' + $r + '|' + (Get-Item -LiteralPath $p).Length) } "
              "else { Write-Output ('CF|' + $r + '|NONE') } }")
    try:
        rc, out, err = run_ps(script, timeout=120)
    except subprocess.TimeoutExpired:
        return {}
    return dict(l.strip().split("|")[1:3] for l in out.splitlines() if l.startswith("CF|") and l.count("|") == 2)



def stop_all():
    """Шаг 3: остановка всех процессов стойки и node gp7-server; None — остановлены, иначе код возврата (3)."""
    say("3. остановка стойки")
    rc, out = ssh_ps("foreach ($n in '%s'.Split(',')) { Stop-Process -Name $n -Force -ErrorAction SilentlyContinue }; "
                     "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'node.exe' -and $_.CommandLine -like '*gp7-server*' } | "
                     "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" % ",".join(PROCS))
    print(out.strip())
    for _ in range(20):
        c = counts()
        if c is not None and not c:               # ★ ревизия 41 Н-4: «не прочитано» ≠ «остановлено» — опрос продолжается
            break
        time.sleep(3)
    c = counts()
    if c is None:
        say("СТОП: счёт процессов стойки после остановки не прочитан (SSH) — дальше не иду, проверьте стойку вручную")
        return 3
    if c:
        say("СТОП: процессы не остановились: %s" % c)
        return 3
    say("   все процессы стойки остановлены")
    return None

TICK_ENV = "ASDA_RESTART_TICK"   # ★ А5.1: команда отсчёта в игре (JSON-список argv), см. шапку
TICK_TIMEOUT = 30                # предел одного вызова команды отсчёта, с


def tick_marks(wait):
    """Оставшиеся секунды, на которых зовётся команда отсчёта: сразу (wait), каждую минуту и за 30 с — по убыванию, > 0."""
    marks = {wait} | set(range(wait - 60, 0, -60)) | ({30} if wait > 30 else set())
    return sorted((m for m in marks if m > 0), reverse=True)


def countdown(wait):
    """Шаг 2: ожидание wait с. С ASDA_RESTART_TICK — вызовы команды отсчёта на отметках tick_marks (сбой — предупреждение),
    общая длина ожидания не меняется. Без переменной — time.sleep(wait), как прежде."""
    raw = os.environ.get(TICK_ENV, "")
    argv = None
    if raw:
        try:
            argv = json.loads(raw)
        except ValueError:
            argv = None
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
            say("   ПРЕДУПРЕЖДЕНИЕ: %s не список строк — отсчёт в игре не идёт" % TICK_ENV)
            argv = None
    if not argv:
        time.sleep(wait)
        return
    t0 = time.time()
    for left in tick_marks(wait):
        delay = (wait - left) - (time.time() - t0)
        if delay > 0:
            time.sleep(delay)
        try:
            p = subprocess.run(argv + [str(left)], capture_output=True, timeout=TICK_TIMEOUT,
                               env=dict(os.environ, PYTHONIOENCODING="utf-8"))
            tail = [x for x in p.stdout.decode("utf-8", "replace").splitlines() if x.strip()]
            say("   отсчёт в игре (%d с): код %d%s" % (left, p.returncode, (" — " + tail[-1][:160]) if tail else ""))
        except Exception as e:
            say("   ПРЕДУПРЕЖДЕНИЕ: отсчёт в игре (%d с) не отправлен: %s" % (left, e))
    rest = wait - (time.time() - t0)
    if rest > 0:
        time.sleep(rest)


def stop_only_main(wait):
    """★ А5.1: --stop-only — объявление (--kind stop), ожидание с отсчётом, штатное завершение GameServer, остановка. Код: 0 —
    процессов стойки 0; 2 — объявление не ушло (стойка не тронута); 3 — процессы не остановились; 7 — счёт процессов не прочитан
    или процессов уже нет (останавливать нечего; объявления не было)."""
    rc_c, out_c = ssh_ps("(Get-Process %s -ErrorAction SilentlyContinue | Measure-Object).Count" % ",".join(PROCS))
    tail = [x.strip() for x in out_c.splitlines() if x.strip()]
    if rc_c != 0 or not tail or not tail[-1].isdigit():
        say("СТОП (--stop-only): число процессов стойки не прочитано (SSH: код %d) — ничего не делаю" % rc_c)
        return 7
    if not int(tail[-1]):
        say("СТОП (--stop-only): процессов стойки нет — останавливать нечего, объявления не будет")
        return 7
    if "--no-announce" not in sys.argv:
        say("1. объявление в Discord (остановка)")
        p = subprocess.run([sys.executable, os.path.join(BOT, "announce_restart.py"), "--minutes", str(max(1, wait // 60)),
                            "--kind", "stop"], cwd=BOT, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        print(p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
        if p.returncode != 0 or "Отправлено" not in p.stdout.decode("utf-8", "replace"):
            say("СТОП: объявление не отправлено — стойку не трогаю")
            return 2
        say("2. ожидание %d с" % wait)
        countdown(wait)
    if "--no-graceful-stop" in sys.argv:
        say("3а. штатное завершение GameServer: пропущено (--no-graceful-stop) — выходы игроков НЕ сохранятся")
    else:
        say("3а. штатное завершение GameServer (SC_CLOSE, сохранение позиции и состояния игроков)")
        try:
            graceful_stop()
        except Exception as e:
            say("   ПРЕДУПРЕЖДЕНИЕ: штатное завершение не прошло — снимаю как раньше: %s" % e)
    stopped = stop_all()
    if stopped is not None:
        return stopped
    # ★ ревизия 41 Н-6: ручной start.bat пропустил бы сброс CharPos и точек входа данжей (шаги 4б2 / 4в)
    say("ИТОГ: стойка остановлена (--stop-only); запуск — ТОЛЬКО restart_stack.py --start-only (панель: stack start), НЕ start.bat "
        "вручную: иначе не будет сброса CharPos и точек входа данжей")
    return 0


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    wait = 180
    start_only = "--start-only" in sys.argv   # ★ 19.11 (А3, ревизия 31): только запуск целиком остановленной стойки
    if start_only and "--deploy" in sys.argv:    # ★ ревизия 32 К-2: не игнорировать молча
        say("--start-only несовместим с --deploy: режим только запускает остановленную стойку, без выкладки")
        return 1
    if "--stop-only" in sys.argv:                # ★ А5.1: объявленная остановка без запуска
        if "--deploy" in sys.argv or start_only:
            say("--stop-only несовместим с --deploy и --start-only: режим только останавливает стойку")
            return 1
        if "--wait" in sys.argv:
            wait = int(sys.argv[sys.argv.index("--wait") + 1])
        return stop_only_main(wait)
    no_deploy = "--no-deploy" in sys.argv or start_only   # ★ 22.10: только перезапуск (например, сервер перечитывает .npc/таблицы)
    if "--deploy" not in sys.argv and not no_deploy:
        say("нужен --deploy <скрипт выкладки> или --no-deploy")
        return 1
    deploy = sys.argv[sys.argv.index("--deploy") + 1] if not no_deploy else ""
    expect = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--expect"]
    if not no_deploy and not os.path.exists(os.path.join(TOOLS, deploy)):
        say("нет скрипта выкладки %s" % deploy)
        return 1
    if "--wait" in sys.argv:
        wait = int(sys.argv[sys.argv.index("--wait") + 1])
    if start_only:
        # счёт процессов обязан быть ПРОЧИТАН: сбой SSH ≠ «процессов нет» (иначе start.bat поднял бы вторые копии)
        rc_c, out_c = ssh_ps("(Get-Process %s -ErrorAction SilentlyContinue | Measure-Object).Count" % ",".join(PROCS))
        tail = [x.strip() for x in out_c.splitlines() if x.strip()]
        if rc_c != 0 or not tail or not tail[-1].isdigit():
            say("СТОП (--start-only): число процессов стойки не прочитано (SSH: код %d) — ничего не запускаю" % rc_c)
            return 7
        c = counts()
        if int(tail[-1]) or c or c is None:       # ★ ревизия 41 Н-4: второй счёт не прочитан — тоже не запускать
            say("СТОП (--start-only): процессы стойки работают: %s — ничего не запускаю и не останавливаю"
                % (c or ("счёт по именам не прочитан" if c is None else tail[-1])))
            return 7
        say("--start-only: процессов стойки нет — объявления, остановки и выкладки не будет, только запуск")

    # ★ 26.10.2026 (инцидент 18:55: стойка стояла ~2 мин из-за паритета): паритет копий канала 2 — ДО объявления и остановки.
    #   Расхождение уже сейчас → стойку не трогаем вовсе (код 6).
    # ★ 26.10.2026: брандмауэр — у каждого exe стойки должно быть входящее правило (канал 2 был закрыт без них).
    if "--skip-firewall" not in sys.argv:
        say("0. правила брандмауэра для exe стойки (только чтение)")
        miss = firewall_missing()
        if miss is None:
            say("   ПРЕДУПРЕЖДЕНИЕ: правила брандмауэра не прочитаны (SSH) — продолжаю")
        elif miss:
            say("СТОП до остановки: нет входящего правила Allow TCP (Private) для: %s — стойка НЕ тронута. Добавить правила "
                "(stack_layout.FIREWALL_EXES, образец в шапке) или --skip-firewall." % ", ".join(miss))
            return 6
        else:
            say("   у всех %d exe стойки правило есть" % len(__import__("stack_layout").FIREWALL_EXES))
    if TWINS and "--skip-parity" not in sys.argv and not start_only:
        say("0. паритет копий канала 2 до остановки (stack_parity, только чтение)")
        p = subprocess.run([sys.executable, os.path.join(TOOLS, "stack_parity.py")], capture_output=True,
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=900)
        print(p.stdout.decode("utf-8", "replace"))
        if p.returncode != 0:
            say("СТОП до остановки: паритета нет (код %d) — стойка НЕ тронута, объявления не было. Разобрать расхождения "
                "(при работающей стойке можно python stack_parity.py --sync) и повторить." % p.returncode)
            return 6

    if "--no-announce" not in sys.argv and not start_only:
        say("1. объявление в Discord")
        p = subprocess.run([sys.executable, os.path.join(BOT, "announce_restart.py"), "--minutes", str(max(1, wait // 60))],
                           cwd=BOT, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        print(p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
        if p.returncode != 0 or "Отправлено" not in p.stdout.decode("utf-8", "replace"):
            say("СТОП: объявление не отправлено — стойку не трогаю")
            return 2
        say("2. ожидание %d с" % wait)
        countdown(wait)                           # ★ А5.1: без ASDA_RESTART_TICK — time.sleep(wait), как прежде

    if start_only:
        say("3. остановка: нет (--start-only, процессов нет)")
    elif "--no-graceful-stop" in sys.argv:
        say("3а. штатное завершение GameServer: пропущено (--no-graceful-stop) — выходы игроков НЕ сохранятся")
    else:
        say("3а. штатное завершение GameServer (SC_CLOSE, сохранение позиции и состояния игроков)")
        try:
            graceful_stop()
        except Exception as e:
            say("   ПРЕДУПРЕЖДЕНИЕ: штатное завершение не прошло — снимаю как раньше: %s" % e)

    if not start_only:
        stopped = stop_all()
        if stopped is not None:
            return stopped


    if no_deploy:
        say("4. выкладка: нет (--no-deploy)")
    p = None if no_deploy else subprocess.run([sys.executable, os.path.join(TOOLS, deploy), "--apply"], capture_output=True,
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    out = p.stdout.decode("utf-8", "replace") if p else "ГОТОВО"
    if p:
        print(out)
    if (p and p.returncode != 0) or "ГОТОВО" not in out:
        say("СТОП: выкладка не прошла (код %d) — стойка ОСТАНОВЛЕНА, нужен ручной запуск start.bat (или откат)" % p.returncode)
        return 4

    # ★ 22.10.2026: patches.ini GameServer пропал после 17:32 неизвестно кем (журнала USN и аудита на H: нет) — без него
    #   DLL стартует с умолчаниями. Перед стартом обе копии обязаны быть на месте; иначе стойка остаётся остановленной.
    # ★ 26.10.2026 (канал 2): копии Ch2_* обязаны совпадать с полем. Выкладка, не знающая про Ch2 (старые deploy_*),
    #   обновила бы только поле — --sync докопирует расходящееся с поля (бэкап прежнего в v2\_backup\<дата>_parity).
    say("4б. паритет копий канала 2 с полем (stack_parity --sync)")
    if not TWINS:
        say("   --single-channel: канал 2 выключен — паритет не сверяется")
    p = subprocess.run([sys.executable, os.path.join(TOOLS, "stack_parity.py"), "--sync"], capture_output=True,
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=900) if TWINS else None
    if p:
        print(p.stdout.decode("utf-8", "replace"))
    # ★ 26.10.2026: после остановки старт блокирует ТОЛЬКО существенное расхождение (код 6: exe/dll/patches.ini/нет папки);
    #   расхождение данных (код 8) или сбой проверки — предупреждение, стойка стартует (простой дороже).
    parity_warn = False
    if p and p.returncode == 6:
        say("СТОП: СУЩЕСТВЕННОЕ расхождение копии канала 2 с полем (exe/dll/patches.ini) после --sync — стойка ОСТАНОВЛЕНА; "
            "разобрать выше и запустить start.bat вручную (или откат выкладки)")
        return 6
    if p and p.returncode != 0:
        parity_warn = True
        say("   ПРЕДУПРЕЖДЕНИЕ: паритет не полный (код %d: 8 — расхождения только в данных, 7 — SSH) — старт продолжается, "
            "разобрать после: python stack_parity.py" % p.returncode)

    # ★ 26.10.2026: не только patches.ini — все критичные файлы (инцидент channel2: сухой прогон удалил 12 общих ini).
    ini = critical_sizes()
    bad = sorted(k for k, v in ini.items() if v == "NONE" or v == "0")
    say("   критичные файлы: %d из %d на месте и не пустые%s" % (len(ini) - len(bad), len(CRITICAL_FILES),
                                                              ("; НЕТ/ПУСТО: " + ", ".join(bad)) if bad else ""))
    if len(ini) != len(CRITICAL_FILES) or bad:
        say("СТОП: нет/пустой критичный файл (или SSH не ответил) — стойка ОСТАНОВЛЕНА; восстановить из v2\\_backup и запустить start.bat вручную")
        return 5

    # ★ 26.10.2026 (волна charpos, баг Player17 «панель Друга показывает своё имя»): сброс устаревших строк dbo.CharPos и
    #   флагов AsdaStoryOp.dbo.Us_member. Оригинал чистит их только при выходе игрока и при РАЗРЫВЕ GameServer с RelayServer
    #   (UpGameServerStart) — при остановке всей стойки Relay гибнет вместе с GS, и игроки, бывшие в игре, остаются «в игре»
    #   (Usernum ≠ −1, State 1): UPCharSoulMate/UPPrivateChat/UPPartyInvite/списки друзей и клана видят их онлайн на чужом слоте.
    #   (State 3 сохраняется) + журнал dbo.CharPosResetLog. Только при остановленной стойке (сверка процессов здесь же).
    #   Не применён SQL / сбой — предупреждение, старт продолжается. --skip-charpos-reset — пропустить.
    # ★ 05.11.2026 (dungeon-relog, пара к AsdaPatch P108): ДО сброса CharPos — пока Usernum ещё показывает «был в игре». Остановка
    #   Stop-Process -Force не даёт GameServer сохранить выход (DisConnectUser → 2003), и у игрока в данже в CharPos остаётся клетка
    #   входа MapInfo, турнирные 10/11 — к выходу их портала; журнал dbo.DungeonRelogLog. Нет процедуры / сбой — предупреждение.
    #   Выключатель: --skip-dungeon-relog-reset (только этот шаг) или --skip-charpos-reset (оба шага сброса CharPos).
    if "--skip-dungeon-relog-reset" in sys.argv or "--skip-charpos-reset" in sys.argv:
        say("4б2. точки входа данжей: пропущено (%s)" % ("--skip-dungeon-relog-reset" if "--skip-dungeon-relog-reset" in sys.argv
                                                       else "--skip-charpos-reset"))
    elif counts() != {}:                          # ★ ревизия 41 Н-4: и «не прочитано» (None) — не выполнять
        say("4б2. точки входа данжей: НЕ выполнено — процессы стойки уже/ещё есть или счёт не прочитан: %s" % counts())
    else:
        say("4б2. точки входа данжей в CharPos (стойка остановлена)")
        rc, out = ssh_ps(r"$o = & sqlcmd -S localhost\SQLEXPRESS -E -d Joy1 -b -h -1 -W -Q 'SET NOCOUNT ON; EXEC dbo.UP_AsdaDungeonRelogReset' 2>&1; "
                         r"Write-Output ($o -join [char]10); Write-Output ('RC=' + $LASTEXITCODE)", timeout=120)
        res = [l.strip() for l in out.splitlines() if l.strip().startswith("DUNGEON|")]
        if "RC=0" in out and res:
            say("   " + res[-1])
        elif "2812" in out:
            say("   ПРЕДУПРЕЖДЕНИЕ: процедуры dbo.UP_AsdaDungeonRelogReset нет (SQL dungeon_relog_fix_20261105.sql не применён) — пропуск")
        else:
            say("   ПРЕДУПРЕЖДЕНИЕ: точки входа данжей не прошли — старт продолжается: %s" % out.strip()[-300:])
    if "--skip-charpos-reset" in sys.argv:
        say("4в. сброс CharPos: пропущен (--skip-charpos-reset)")
    elif counts() != {}:                          # ★ ревизия 41 Н-4: и «не прочитано» (None) — не выполнять
        say("4в. сброс CharPos: НЕ выполнен — процессы стойки уже/ещё есть или счёт не прочитан: %s" % counts())
    else:
        say("4в. сброс устаревших строк CharPos/Us_member (стойка остановлена)")
        # без двойных кавычек: ssh_ps заворачивает команду в powershell -Command "…"; запрос — в одинарных кавычках PowerShell
        rc, out = ssh_ps(r"$o = & sqlcmd -S localhost\SQLEXPRESS -E -d Joy1 -b -h -1 -W -Q 'SET NOCOUNT ON; EXEC dbo.UP_AsdaCharPosReset' 2>&1; "
                         r"Write-Output ($o -join [char]10); Write-Output ('RC=' + $LASTEXITCODE)", timeout=120)
        res = [l.strip() for l in out.splitlines() if l.strip().startswith("CHARPOS|")]
        if "RC=0" in out and res:
            say("   " + res[-1])
        elif "2812" in out:
            say("   ПРЕДУПРЕЖДЕНИЕ: процедуры dbo.UP_AsdaCharPosReset нет (SQL charpos_fix_20261026.sql не применён) — пропуск")
        else:
            say("   ПРЕДУПРЕЖДЕНИЕ: сброс CharPos не прошёл — старт продолжается: %s" % out.strip()[-300:])

    say("5. запуск start.bat в интерактивной сессии администратора")
    task = "AsdaStackStart_coord"
    start_bat = V2_LOCAL + r"\start.bat"
    rc, out = ssh_ps("schtasks /Create /F /TN %s /SC ONCE /ST 23:59 /RU Administrator /IT /TR '%s'; schtasks /Run /TN %s" % (task, start_bat, task))
    print(out.strip())
    time.sleep(75)
    rc, out = ssh_ps("schtasks /Delete /F /TN %s" % task)
    print(out.strip())

    say("6. проверка")
    c = {}
    for _ in range(20):
        c = counts() or {}                        # ★ ревизия 41 Н-4: не прочитано — как «не все», опрос продолжается
        if all(c.get(k, 0) >= v for k, v in EXPECT.items()):
            break
        time.sleep(5)
    ok_procs = all(c.get(k, 0) >= v for k, v in EXPECT.items())
    say("   процессы: %s %s" % (c, "OK" if ok_procs else "НЕ ВСЕ"))
    # ★ 22.10.2026: журнал патчей читается ПО SSH с совместным доступом (FileShare.ReadWrite) и с пределом времени.
    #   Прежнее чтение по сетевой папке повисло на 3,5 часа: GameServer держит файл открытым на запись (SMB/oplock).
    # ★ 31.10.2026 (fix-check-started): разбор — общий patchlog.check_folder: блок ПОСЛЕДНЕГО запуска (последний «Хост   :»),
    #   обязательны «=== итог» с «ошибок 0» и «[OK] <--expect>»; провал — [MISMATCH]/[ОШИБКА]/[ERR]/[FAIL] в установке,
    #   [ВЫКЛ] ожидаемого, «Version не поддерживается», MasterEnable=0, PID шапки не среди работающих процессов папки
    #   (новый процесс в журнал не писал — прежде брался прежний старт того же дня).
    ok_patch = True
    # ★ 27.10.2026 (L08): ожидания вида L<NN>_… — патчи LoginPatch.dll; их проверяет журнал LoginManager (заголовок сессии
    #   «LoginPatch — старт …»). Остальные — AsdaPatch.dll в GameServer, как раньше. Без L-ожиданий LoginManager не читается.
    import re
    import patchlog
    login_expect = [n for n in expect if re.match(r"L\d\d[a-z]?_", n)]
    gs_expect = [n for n in expect if n not in login_expect]
    logs = list(GS_FOLDERS) + (["LoginManager"] if login_expect else [])
    oks = {}
    for d in logs:
        ok, info = patchlog.check_folder(d, login_expect if d == "LoginManager" else gs_expect, log=lambda s: say("   " + s))
        ok_patch = ok_patch and ok
        if info.get("run"):
            oks[d] = info["ok_count"]
    for twin, field in TWINS.items():   # ★ 26.10: у копии канала 2 стоят те же патчи, что у поля
        if twin in oks and field in oks:
            same = oks[twin] == oks[field]
            say("   %s: [OK] %d, у %s %d — %s" % (twin, oks[twin], field, oks[field], "как у поля" if same else "НЕ КАК У ПОЛЯ"))
            ok_patch = ok_patch and same
    if parity_warn:
        say("   паритет копий канала 2: НЕ полный (см. шаг 4б)")
    say("ИТОГ: %s" % ("стойка поднята, патчи стоят" if ok_procs and ok_patch and not parity_warn else "ЕСТЬ ПРОБЛЕМЫ — смотри выше"))
    return 0 if ok_procs and ok_patch else 5


# ★ 20.11.2026 (админ-центр, ревизия 41 В-1): ОДИН restart_stack.py на ПК за раз — файл-замок рядом со скриптом (PID владельца).
#   Второй запуск (вторая консоль, задание панели во время рестарта набора, ручной запуск) — код 8, ничего не делается. Замок умершего
#   процесса (PID не жив) снимается. Взаимоисключение панели (adm.job) — поверх этого, но не заменяет его для ручных запусков.
LOCK_FILE = os.path.join(TOOLS, "_restart_stack.lock")


def _pid_alive(pid):
    """Жив ли процесс pid (Windows: OpenProcess + GetExitCodeProcess = STILL_ACTIVE; без сигналов — os.kill на Windows убивает)."""
    import ctypes
    k = ctypes.windll.kernel32
    h = k.OpenProcess(0x1000, False, int(pid))          # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    try:
        code = ctypes.c_ulong()
        return bool(k.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259
    finally:
        k.CloseHandle(h)


def acquire_lock(path=LOCK_FILE, alive=_pid_alive):
    """Взять замок → (True, None) | (False, PID владельца)."""
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                other = int(open(path, encoding="ascii").read().strip() or 0)
            except (OSError, ValueError):
                other = 0
            if other and alive(other):
                return False, other
            try:
                os.remove(path)                   # замок умершего процесса
            except OSError:
                return False, other
            continue
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(str(os.getpid()))
        return True, None
    return False, None


def release_lock(path=LOCK_FILE):
    try:
        if int(open(path, encoding="ascii").read().strip() or 0) == os.getpid():
            os.remove(path)
    except (OSError, ValueError):
        pass


ACTIVITY_FILE = r"@@ASTORY_SERVER_ROOT@@\stack_activity.txt"         # ★ ревизия 77 В-2: отметка для domains/notify.py (служба панели читает её на сервере)
ACTIVITY_RUN_MIN, ACTIVITY_DONE_MIN, ACTIVITY_STOP_MIN = 45, 15, 720


def mark_activity(phase, minutes, code=None):
    """Отметка «идёт управление стойкой» на сервере (часы сервера, UTC) → True, если записана. Сбой — предупреждение, рестарт идёт дальше."""
    cmd = ("$u = (Get-Date).ToUniversalTime(); Set-Content -LiteralPath '%s' -Encoding ASCII -Value ('phase=%s until=' + "
           "$u.AddMinutes(%d).ToString('yyyyMMddTHHmmssZ') + ' at=' + $u.ToString('yyyyMMddTHHmmssZ') + ' code=%s pid=%d')"
           % (ACTIVITY_FILE, phase, int(minutes), "" if code is None else int(code), os.getpid()))
    try:
        rc, out = ssh_ps(cmd, timeout=60)
    except Exception as ex:                       # SSH не запустился — рестарт всё равно идёт
        rc, out = -1, str(ex)
    if rc != 0:
        say("ПРЕДУПРЕЖДЕНИЕ: отметка «идёт управление стойкой» не записана (код %s) — уведомление «стойка не поднялась» может прийти ложно" % rc)
        return False
    return True


def read_activity():
    """Прежняя отметка на сервере (строка) или None (нет файла, не прочитана)."""
    try:
        rc, out = ssh_ps("if (Test-Path -LiteralPath '%s') { Get-Content -LiteralPath '%s' -TotalCount 1 }" % (ACTIVITY_FILE, ACTIVITY_FILE), timeout=60)
    except Exception:
        return None
    line = (out or "").strip().splitlines()[0].strip() if rc == 0 and (out or "").strip() else ""
    return line if line and all(c.isalnum() or c in "=: " for c in line) else None


def restore_activity(line):
    """Вернуть прежнюю отметку как была (только буквы, цифры, «=», «:» и пробелы — проверено read_activity)."""
    try:
        rc, _out = ssh_ps("Set-Content -LiteralPath '%s' -Encoding ASCII -Value '%s'" % (ACTIVITY_FILE, line), timeout=60)
    except Exception:
        rc = -1
    if rc != 0:
        say("ПРЕДУПРЕЖДЕНИЕ: прежняя отметка «идёт управление стойкой» не возвращена (код %s)" % rc)


def run_locked():
    """Точка входа скрипта: --help — шапка без действий; иначе main() под файлом-замком (занято — код 8)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--help" in sys.argv or "-h" in sys.argv:
        print(open(os.path.abspath(__file__), encoding="utf-8").read().split("\nimport json")[0])
        return 0
    ok, other = acquire_lock()
    if not ok:
        say("СТОП: уже работает другой restart_stack.py (PID %s, замок %s) — ничего не делаю" % (other or "?", LOCK_FILE))
        return 8
    rc, prev = None, None
    try:
        prev = read_activity()
        mark_activity("run", ACTIVITY_RUN_MIN)
        rc = main()
        return rc
    finally:
        try:
            if rc in (1, 7) and prev:
                restore_activity(prev)             # ★ р78 К-2: стойка не тронута — прежняя отметка остаётся
            elif rc in (1, 7):
                mark_activity("done", 0, rc)       # прежней не было — отметка «run» сразу истекает
            elif rc == 0 and "--stop-only" in sys.argv:
                mark_activity("stopped", ACTIVITY_STOP_MIN, rc)
            else:
                mark_activity("done", ACTIVITY_DONE_MIN, rc)
        finally:
            release_lock()


if __name__ == "__main__":
    sys.exit(run_locked())
