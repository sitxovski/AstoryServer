# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# test_patchlog.py — проверка общего разбора журнала патчей patchlog на синтетических журналах (31.10.2026, fix-check-started).
#   judge: суточный журнал с ДВУМЯ стартами — первый удачный, второй с каждым видом провала → провал; один удачный → ок;
#   шапка старта далеко над паспортом (строки Config «+ раздел … добавлен»), [FAIL], шапки нет (PID не подтверждён).
#   read_folder: тот же PowerShell, что идёт по SSH, на ЛОКАЛЬНОЙ временной папке — выбор файла строго PatchLog_<8 цифр>.txt,
#   полночь (последний запуск в файле прошлого дня), обрезка по пределу байт с отбросом первой неполной строки, нет журнала.
#   dll_builds.accept: своя сборка / более поздняя сборка цепочки при подтверждённом журнале — ок; иначе провал.
#   Сервер не нужен. Запуск: python test_patchlog.py   (код 0 — все случаи как ожидалось)
#   --live: дополнительно по SSH (только чтение): предел времени (3 с на команду в 30 с → отказ, не зависание) и P98/P99 на dev.
import base64
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import patchlog   # noqa: E402

try:   # run_checks перехватывает вывод в файл: консольная cp1251 не знает «→» — без этого тест падал UnicodeEncodeError
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

P = "P98_PremiumStackAmount"


def run_block(pid, body, total="=== итог: применено 76, пропущено 2, ошибок 0 ===", tail=(), config=0, head=True):
    """Один запуск в формате Log.cpp/dllmain: разделитель, шапка (head), config строк Config «+ раздел … добавлен», паспорт,
    установка, итог, строки работы."""
    ls = ["", "[14:38:48] ==================================================================="]
    if head:
        ls.append("[14:38:48] AsdaPatch — старт 2026-10-31 14:38:48, PID %d" % pid)
    ls += ["[14:38:48] + раздел [P%02d_New] добавлен в patches.ini (по умолчанию)" % (60 + i) for i in range(config)]
    ls += ["[14:38:48] Сборка : …", "[14:38:48] Хост   : @@ASTORY_SERVER_ROOT_ESC@@\\Working_ASDA\\v2\\GameServer\\GameServer.exe",
           "[14:38:48] База   : 0x00400000 (ожидается 0x00400000)"]
    ls += ["[14:38:49] " + l for l in body]
    if total:
        ls.append("[14:38:51] " + total)
    ls += ["[15:00:00] " + l for l in tail]
    return "\r\n".join(ls) + "\r\n"


GOOD = ["MasterEnable=1 — установка патчей (78 в реестре):", "  образ-хозяин: GameServer.exe",
        "    P98: премиум-почта 11006 — площадка 0x0045A1B2",
        "  [OK]       P98_PremiumStackAmount — количество премиум-предмета", "  [OK]       P99_UpgradeSplitStone — разделение",
        "  [ВЫКЛ]     P09_DiagTrace — диагностика"]
NEED = ("P98: премиум-почта 11006",)


def mod(repl):
    """GOOD с заменой строк: {подстрока: новая строка или None (удалить)}; ключ '+' — добавить строки в конец установки."""
    out = []
    for l in GOOD:
        k = next((k for k in repl if k != "+" and k in l), None)
        if k is None:
            out.append(l)
        elif repl[k] is not None:
            out.append(repl[k])
    return out + list(repl.get("+", []))


FIRST = run_block(1000, GOOD)
CASES = [   # (имя, журнал, pids, ожидается ok)
    ("один удачный старт", FIRST, [1000], True),
    ("два удачных, PID второго", FIRST + run_block(2000, GOOD), [2000], True),
    ("шапка на 12 строк Config выше паспорта", FIRST + run_block(2000, GOOD, config=12), [2000], True),
    ("второй без шапки, прежняя шапка выше (не брать)", FIRST + run_block(1000, GOOD, head=False), [1000], False),
    ("шапки нет, PID не сверяется (pids=None)", run_block(1000, GOOD, head=False), None, True),
    ("второй: [MISMATCH] ожидаемого", FIRST + run_block(2000, mod({"[OK]       P98": "  [MISMATCH] P98_PremiumStackAmount — …   * НЕ ПОСТАВЛЕН (см. строки выше)"}),
                                                       "=== итог: применено 75, пропущено 2, ошибок 1 ==="), [2000], False),
    ("второй: [MISMATCH] прочего, итог «ошибок 0» подделан", FIRST + run_block(2000, mod({"[OK]       P99": "  [MISMATCH] P99_UpgradeSplitStone — …"})), [2000], False),
    ("второй: [ОШИБКА] прочего", FIRST + run_block(2000, mod({"[OK]       P99": "  [ОШИБКА]   P99_UpgradeSplitStone — …   * НЕ ПОСТАВЛЕН"}),
                                                  "=== итог: применено 75, пропущено 2, ошибок 1 ==="), [2000], False),
    ("второй: метка ERR в установке", FIRST + run_block(2000, mod({"+": ["    [ERR] P98 не установлен: площадка занята"]})), [2000], False),
    ("второй: метка FAIL в установке", FIRST + run_block(2000, mod({"+": ["    P73: [FAIL] мост не поднят"]})), [2000], False),
    ("второй: [ВЫКЛ] ожидаемого", FIRST + run_block(2000, mod({"[OK]       P98": "  [ВЫКЛ]     P98_PremiumStackAmount — …"}),
                                                   "=== итог: применено 75, пропущено 3, ошибок 0 ==="), [2000], False),
    ("второй: Version не поддерживается", FIRST + run_block(2000, ["! Version=55 не поддерживается этой сборкой (ожидается 56) — патчи не ставятся."],
                                                           total=""), [2000], False),
    ("второй: MasterEnable=0", FIRST + run_block(2000, ["MasterEnable=0 — НИ ОДИН патч не ставится, сервер работает как сток.",
                                                        "   (это штатный режим проверки каркаса; после успешного старта поставить 1)"],
                                                 "=== итог: применено 0, пропущено 0, ошибок 0 ==="), [2000], False),
    ("второй: оборван без итога", FIRST + run_block(2000, GOOD[:2], total=""), [2000], False),
    ("второй: «ошибок 1» в итоге", FIRST + run_block(2000, GOOD, "=== итог: применено 75, пропущено 2, ошибок 1 ==="), [2000], False),
    ("второй: нет обязательной строки", FIRST + run_block(2000, mod({"P98: премиум-почта": None})), [2000], False),
    ("второй старт в журнал не писал (PID прежний)", FIRST, [2000], False),
    ("процесс не работает", FIRST, [], False),
    ("после итога: [ОШИБКА] ожидаемого", FIRST + run_block(2000, GOOD, tail=["    P98: [ОШИБКА] запись не прошла"]), [2000], False),
    ("после итога: «[P98] … [ERR]» ожидаемого", FIRST + run_block(2000, GOOD, tail=["[P98] [ERR] запись не прошла"]), [2000], False),
    ("после итога: [ОШИБКА] прочего — сведения", FIRST + run_block(2000, GOOD, tail=["    P61: [ОШИБКА] ключ не загрузился при первом соединении"]),
     [2000], True),
    ("нет паспорта", "[00:00:00] что-то\r\n", [1], False),
]


def local_ps(script, timeout):
    """Тот же PowerShell, что patchlog шлёт по SSH (PS_LIB deploy_p90 + скрипт), — на этой машине."""
    from deploy_p90 import PS_LIB
    enc = base64.b64encode((PS_LIB + script).encode("utf-16-le")).decode("ascii")
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc], capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace").strip()


def read_folder_cases():
    """read_folder на локальной временной папке v2. → число несовпадений."""
    bad = 0
    root = tempfile.mkdtemp(prefix="patchlog_test_")
    try:
        def put(folder, name, text):
            d = os.path.join(root, folder, "Log", "Log_Patch")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, name), "wb") as f:
                f.write(text.encode("cp1251"))

        def one(name, folder, want_file, want_ok, max_bytes=patchlog.MAX_BYTES, want_err=False, extra=None):
            nm, text, pids, err = patchlog.read_folder(folder, timeout=60, max_bytes=max_bytes, v2=root, runner=local_ps)
            ok = False
            if not err:
                ok = patchlog.judge(text, [P], NEED, None)[0]
            good = (bool(err) == want_err) and (want_err or (nm == want_file and ok == want_ok)) and (extra is None or extra(text))
            print("%s read_folder: %-46s → файл %s, %s%s" % ("[OK]  " if good else "[ПРОВАЛ]", name, nm or "—",
                                                            "ошибка: " + err[:80] if err else ("ок" if ok else "провал"),
                                                            "" if pids == [] else ", pids %s" % pids))
            return 0 if good else 1

        # выбор файла: «PatchLog_20261031_копия.txt» (сортируется выше) и «PatchLog_99999999 - копия.txt» не по шаблону
        put("GS1", "PatchLog_20261030.txt", run_block(900, GOOD))
        put("GS1", "PatchLog_20261031.txt", FIRST + run_block(2000, GOOD))
        put("GS1", "PatchLog_20261031_копия.txt", run_block(3000, mod({"[OK]       P98": "  [MISMATCH] P98_PremiumStackAmount"})))
        put("GS1", "PatchLog_99999999 - копия.txt", run_block(3000, GOOD[:1], total=""))
        bad += one("строго PatchLog_<8 цифр>.txt, самый поздний", "GS1", "PatchLog_20261031.txt", True)
        # полночь: стойка поднята 30.10 23:50, работает 31.10 — строки работы идут в файл дня старта, нового файла нет
        put("GS2", "PatchLog_20261029.txt", run_block(800, GOOD))
        put("GS2", "PatchLog_20261030.txt", run_block(900, GOOD, tail=["P98: [сведения] 00:05 — работа после полуночи"]))
        bad += one("полночь: последний запуск в файле прошлого дня", "GS2", "PatchLog_20261030.txt", True)
        # обрезка: предел меньше файла — читается хвост, первая (неполная) строка отброшена; хвост — последний запуск целиком
        big = "".join(run_block(100 + i, GOOD) for i in range(40)) + run_block(2000, GOOD)
        put("GS3", "PatchLog_20261031.txt", big)
        lim = len(run_block(2000, GOOD).encode("cp1251")) + 37        # 37 байт — середина строки прежнего запуска
        tail_lines = big.encode("cp1251")[-lim:].decode("cp1251").split("\r\n")
        bad += one("обрезка по пределу байт, первая строка отброшена", "GS3", "PatchLog_20261031.txt", True, max_bytes=lim,
                   extra=lambda t: t.splitlines()[0] == tail_lines[1] and t.splitlines()[0] != tail_lines[0])
        # нет журнала
        os.makedirs(os.path.join(root, "GS4", "Log", "Log_Patch"), exist_ok=True)
        bad += one("журнала нет (NOLOG)", "GS4", "", False, want_err=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return bad


def main():
    bad = 0
    for name, text, pids, want in CASES:
        ok, why, info = patchlog.judge(text, [P], NEED, pids)
        good = ok == want
        bad += 0 if good else 1
        # причины — только при несовпадении: run_checks считает метки «[FAIL]»/«[!!]» в выводе провалами
        print("%s %-50s → %s%s" % ("[OK]  " if good else "[ПРОВАЛ]", name, "ок" if ok else "провал",
                                   "" if good else ("; " + " | ".join(why))[:300]))
    # cp1251 (Log.cpp пишет WideCharToMultiByte 1251) и UTF-8 одинаково
    for enc in ("cp1251", "utf-8"):
        ok, why, _ = patchlog.judge(patchlog.decode_log(FIRST.encode(enc)), [P], NEED, [1000])
        bad += 0 if ok else 1
        print("%s декодирование %s → %s" % ("[OK]  " if ok else "[ПРОВАЛ]", enc, "ок" if ok else why))
    # реестр сборок DLL (dll_builds.accept): своя; новее при подтверждённом журнале — ок; новее без журнала, старее, незнакомый — провал
    import dll_builds
    ch = dll_builds.CHAINS["AsdaPatch"]
    for name, got, want, log_ok, exp in [("своя сборка", ch[-2][0], ch[-2][0], True, True),
                                         ("сборка новее, журнал ок", ch[-1][0], ch[-2][0], True, True),
                                         ("сборка новее, журнал не подтвердил", ch[-1][0], ch[-2][0], False, False),
                                         ("сборка старее", ch[-3][0], ch[-2][0], True, False),
                                         ("незнакомый md5", "0" * 32, ch[-2][0], True, False)]:
        r = dll_builds.accept("AsdaPatch", got, want, log_ok, "x", log=lambda s: None)
        bad += 0 if r == exp else 1
        print("%s dll_builds: %-36s → %s" % ("[OK]  " if r == exp else "[ПРОВАЛ]", name, "принять" if r else "провал"))
    bad += read_folder_cases()
    if "--live" in sys.argv:
        rc, out = patchlog._ssh_ps("Start-Sleep -Seconds 30; Write-Output DONE", 3)
        good = rc == -1
        bad += 0 if good else 1
        print("%s предел времени SSH 3 с на команду 30 с → код %d (%s)" % ("[OK]  " if good else "[ПРОВАЛ]", rc, out[-80:]))
        import stack_layout
        for d in stack_layout.GS_FOLDERS:
            ok, _ = patchlog.check_folder(d, ["P98_PremiumStackAmount", "P99_UpgradeSplitStone"],
                                          ["P98: премиум-почта 11006", "P99: разделение улучшения"])
            bad += 0 if ok else 1
    print("ИТОГ: %s" % ("все случаи как ожидалось" if not bad else "НЕ СОШЛОСЬ: %d" % bad))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
