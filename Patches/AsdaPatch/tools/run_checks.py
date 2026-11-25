# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# run_checks.py — ПАРАЛЛЕЛЬНЫЙ регресс всех проверок на ИТОГОВЫХ DLL основных папок (15.10.2026, волна p71p72n18).
#   Та же матрица, что у Reports/anticheat/wAUTOBAN_logs/run_checks.py (autoban 14.10; последовательный прогон ≈ 50–60 мин):
#   verify_* (AsdaPatch/tools, AsdaSecure/tools), stand_tick_locks.py, стенды GS ×3 образа × Mode, NPC ×3, ac0 db, stand_map ×3
#   (по умолчанию и «все включены» с ТЕСТОВЫМ ключом во временной копии), stand_acjournal down/flood/filerows/filecap,
#   AsdaSecure stand_secure/stand_wire/stand_nocng/stand_b7d_locks (+ стенды fix2c/d/e), LoginPatch test_l01/l04/l04c/l06 + host_load.
#   Серверы НЕ запускаются: стенды отображают образ exe в свой процесс как данные и зовут фрагменты (принятая практика).
#   Образы NpcServer/DBManager берутся из зеркала стойки (srv_paths.ROOT) и копируются во временную папку.
#
# ★ 22.10.2026 (слово владельца «если шара недоступна — ssh»): \@@ASTORY_SERVER_HOSTNAME@@ НЕ используется. Все файлы стойки, которые читают
#   задания (образы GS/NPC/DBM/LM, таблицы), — из локального зеркала tools/_srv_mirror/ (корень — srv_paths.py). В начале
#   прогона run_checks сам зовёт srv_mirror.update(): по SSH (только чтение, FileStream с FileShare.ReadWrite, предел времени
#   на шаг, md5) докачивает изменившееся, неизменное берёт из кэша. SSH недоступен — прогон на прежнем зеркале (предупреждение);
#   файлов в зеркале нет — отказ (код 2). Ключи: ASDA_NO_MIRROR_UPDATE=1 — не обновлять зеркало; ASDA_SRV_ROOT=<папка> —
#   другой корень; ASDA_USE_SMB=1 — по-старому с шары (только если она точно жива). Снять зеркало отдельно: python srv_mirror.py.
#
# ★ Чем отличается: задания собираются в список и исполняются пулом (по умолчанию 8 воркеров, ключ --jobs N).
#   • verify_*.py и стенды AsdaSecure/LoginPatch побочных эффектов на диске не имеют — идут полностью параллельно;
#   • каждый стенд GS/NPC/DB/map/acjournal пишет в СВОЮ папку (ConfigSet\patches.ini, Log\…) — задания с одной папкой
#     сериализуются замком на папку (ключ = cwd), разные стенды идут параллельно;
#   • сводка summary.txt — в исходном порядке заданий, построчный вывод — по мере завершения (с длительностью).
# Запуск: python run_checks.py [только_группа] [--jobs N]. RUN_OUT — папка логов (по умолчанию рядом с этим файлом в run_<дата_время>/).
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

T = r"@@ASTORY_DEV_ROOT@@\AstoryServer\Patches"
# ★ P73 (w73, 2026-10-16): папка AsdaPatch — та, где лежит этот файл (копия w73 гоняет СВОЮ DLL и свои стенды); ASDA_AP — явная.
AP = os.environ.get("ASDA_AP") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from srv_paths import ROOT as SHARE, USE_SMB   # ★ 22.10.2026: корень стойки — зеркало по SSH (srv_mirror.py); шара только ASDA_USE_SMB=1
import srv_mirror
IMG = r"@@ASTORY_DEV_ROOT@@\Reports\anticheat\wA7_logs\img"
GS = {"stock": os.path.join(IMG, "gs_stock.exe"), "live": os.path.join(IMG, "gs_live.exe"), "indun": os.path.join(IMG, "gs_indun.exe")}
NPC_SRC = {"stock": SHARE + "/AsdaStory/NpcServer/NpcServer.exe", "live": SHARE + "/v2/NpcServer/NpcServer.exe",
           "indun": SHARE + "/v2/Indun_NpcServer/NpcServer.exe"}
DBM_SRC = SHARE + "/v2/DBManager/DBManager.exe"
# ★ P77 (22.10.2026): копирование образов NpcServer/DBManager с шары \\@@ASTORY_SERVER_HOSTNAME@@ повисло (>19 мин, SMB-чтение файлов работающих процессов —
#   грабля 22.10). ASDA_SRV_IMG_DIR — локальная папка с npc_stock.exe / npc_live.exe / npc_indun.exe / dbm_live.exe (снятыми по SSH,
#   FileStream с FileShare.ReadWrite); без ключа — прежнее чтение с шары.
_SRV_IMG = os.environ.get("ASDA_SRV_IMG_DIR")
if _SRV_IMG:
    NPC_SRC = {k: os.path.join(_SRV_IMG, "npc_%s.exe" % k) for k in ("stock", "live", "indun")}
    DBM_SRC = os.path.join(_SRV_IMG, "dbm_live.exe")
# ★ EAC §8.6 (R3-05, 16.10): "gs_stand" — стендовая сборка той же основной (ASDA_PATCH_STAND, тестовые экспорты P73) для stand_p73;
#   все прочие стенды и verify — на рабочей out\AsdaPatch.dll (тестовых экспортов P73 в ней нет).
DLL = {"gs": os.path.join(AP, "out", "AsdaPatch.dll"), "gs_stand": os.path.join(AP, "out", "stand", "AsdaPatch.dll"), "db": os.path.join(T, "DBPatch", "out", "DBPatch.dll"),
       "npc": os.path.join(T, "AddonNPC", "out", "AddonNPC.dll"), "lm": os.path.join(T, "LoginPatch", "out", "LoginPatch.dll")}

HERE = os.environ.get("RUN_OUT") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_" + time.strftime("%Y%m%d_%H%M%S"))
JOBS = []            # (group, name, cmd, cwd, key, timeout) — в порядке добавления
RESULTS = {}         # index -> (group, name, rc, ok, bad, tail, sec)
LOCKS = {}           # key -> Lock (сериализация заданий с общей папкой)
SKIPPED = []         # задания, снятые ключом ASDA_SKIP_JOBS
LOCKS_GUARD = threading.Lock()
PRINT = threading.Lock()
# локальные копии образов GS для verify-скриптов (каждый читает свой ключ; без ключа — из зеркала стойки srv_paths.ROOT)
ENV = dict(os.environ)
for k in ("P57_IMG_DIR", "P60_IMG_DIR", "P62_IMG_DIR", "P63_IMG_DIR", "ASDA_GS_IMG_DIR", "P65_IMG_DIR", "P66_IMG_DIR",
          "P67_IMG_DIR", "P68_IMG_DIR", "P71_IMG_DIR", "P72_IMG_DIR", "P73_IMG_DIR", "P74_IMG_DIR", "P75_IMG_DIR", "P76_IMG_DIR", "P77_IMG_DIR", "P80_IMG_DIR", "P81_IMG_DIR", "P82_IMG_DIR", "P87_IMG_DIR", "P88_IMG_DIR"):
    ENV.setdefault(k, IMG)


def md5(p):
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def add(group, name, cmd, cwd, key=None, timeout=900):
    """Добавить задание. key — замок (None = без побочных эффектов, полностью параллельно)."""
    # ★ P77 (22.10.2026): ASDA_SKIP_JOBS — имена заданий через запятую, которые не ставить (например, verify, читающие образы
    #   только с шары \\@@ASTORY_SERVER_HOSTNAME@@, пока SMB висит). Пропуск печатается и попадает в сводку как «ПРОПУЩЕНО».
    if name in [s.strip() for s in os.environ.get("ASDA_SKIP_JOBS", "").split(",") if s.strip()]:
        SKIPPED.append("%s/%s" % (group, name))
        return
    JOBS.append((group, name, cmd, cwd, key, timeout))


def lock_for(key):
    with LOCKS_GUARD:
        if key not in LOCKS:
            LOCKS[key] = threading.Lock()
        return LOCKS[key]


# ★ 04.11.2026: отрицательные контроли AsdaSecure — имя задания → строка вывода, подтверждающая воспроизведение дефекта
EXPECT_FAIL = {
    "stand_limit4096_old_expect_fail": r"ПРОВАЛОВ: \d+ \(Н-1 воспроизведён\)",
    "stand_backlog_old_expect_fail": r"переполнение досылки ВОСПРОИЗВЕДЕНО",
}


def execute(idx):
    """Исполнить задание idx: лог в <group>/<name>.txt; итог — rc, [OK], [!!]/[ПРОВАЛ]."""
    group, name, cmd, cwd, key, timeout = JOBS[idx]
    os.makedirs(os.path.join(HERE, group), exist_ok=True)
    log = os.path.join(HERE, group, name + ".txt")
    lk = lock_for(key) if key else None
    if lk:
        lk.acquire()
    t0 = time.time()
    try:
        try:
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout, env=ENV)
            out = r.stdout + r.stderr
            rc = r.returncode
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b"") + b"\n== TIMEOUT ==\n"
            rc = -9
        except OSError as e:
            out = ("== НЕ ЗАПУЩЕНО: %s ==\n" % e).encode("utf-8")
            rc = -8
    finally:
        if lk:
            lk.release()
    sec = time.time() - t0
    txt = None
    for enc in ("utf-8", "cp1251", "cp866"):
        try:
            txt = out.decode(enc); break
        except UnicodeDecodeError:
            continue
    if txt is None:
        txt = out.decode("utf-8", errors="replace")
    with open(log, "w", encoding="utf-8", newline="\n") as f:
        f.write("$ " + " ".join(cmd) + "\n" + txt)
    ok = len(re.findall(r"\[OK\]", txt))
    bad = len(re.findall(r"\[!!\]|\[ПРОВАЛ\]|\[FAIL\](?! 0\b)", txt))   # ★ 04.11.2026: «ИТОГ: [OK] n, [FAIL] 0» — не провал
    tail = [l for l in txt.splitlines() if re.search(r"ИТОГ|ВСЁ СОШЛОСЬ|ПРОВАЛОВ|итог:|СТЕНД|ВСЕ ПРОВЕРКИ|ПЕРЕСЕЧЕНИЙ", l)]
    last = tail[-1].strip() if tail else ""
    # ★ 04.11.2026: отрицательные контроли — тот же стенд против СТАРОГО кода моста (фикстуры AsdaSecure stand\old_fix2b / old_fix2c)
    #   ОБЯЗАН воспроизвести исходный дефект. Пройден = процесс провалился (rc ≠ 0) И в выводе есть строка воспроизведения;
    #   контроль, который перестал воспроизводить (rc 0 или нет строки), — провал (стенд потерял чувствительность).
    if name in EXPECT_FAIL:
        repro = re.search(EXPECT_FAIL[name], txt) is not None
        last = "ожидаемый провал (rc %d): %s" % (rc, last) if rc != 0 and repro else "КОНТРОЛЬ НЕ ВОСПРОИЗВЁЛ ДЕФЕКТ (rc %d): %s" % (rc, last)
        rc, bad = (0, 0) if (rc != 0 and repro) else (1, max(bad, 1))
    RESULTS[idx] = (group, name, rc, ok, bad, last, sec)
    with PRINT:
        print("%-8s %-30s rc=%-3d OK=%-5d bad=%-3d %5.0fs %s" % (group, name, rc, ok, bad, sec, last[:100]), flush=True)
    return rc


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = [a for a in sys.argv[1:]]
    jobs_n = 8
    if "--jobs" in args:
        i = args.index("--jobs"); jobs_n = max(1, int(args[i + 1])); del args[i:i + 2]
    only = args[0] if args else None
    want = lambda g: only is None or only == g
    os.makedirs(HERE, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="regress_checks_")
    print("RUN_OUT:", HERE, " воркеров:", jobs_n)
    # ★ 22.10.2026: зеркало файлов стойки по SSH (не шара) — до постановки заданий
    if USE_SMB:
        print("ФАЙЛЫ СТОЙКИ: шара", SHARE, "(ASDA_USE_SMB=1)")
    else:
        print("ФАЙЛЫ СТОЙКИ: зеркало", SHARE)
        if os.environ.get("ASDA_NO_MIRROR_UPDATE") == "1" or os.environ.get("ASDA_SRV_ROOT"):
            miss = srv_mirror.present() if not os.environ.get("ASDA_SRV_ROOT") else []
            print("  обновление зеркала отключено ключом%s" % ("; нет: " + ", ".join(miss) if miss else ""))
        else:
            mrc = srv_mirror.update(log=lambda m: print("  " + m, flush=True))
            if mrc == 2:
                sys.exit("в зеркале стойки нет нужных файлов, а SSH их не отдал — прогон невозможен (см. выше)")
            if mrc == 1:
                print("  [ВНИМАНИЕ] зеркало обновлено не полностью — прогон на прежних копиях (см. _srv_mirror/_manifest.json)")
    print("DLL:", {k: md5(v) for k, v in DLL.items()})
    py = sys.executable
    st = os.path.join(AP, "tools")
    E = lambda n: os.path.join(st, "stand_" + n, "stand_%s.exe" % n)
    C = lambda n: os.path.join(st, "stand_" + n)
    # ── verify (без побочных эффектов → параллельно) ──
    if want("verify"):
        for v in ["ac0", "dll", "a5b", "p38", "p41", "p42", "p43", "p44", "p46", "p55", "p56", "p57", "p60", "p62", "p63",
                  "p64", "p65", "p66", "p67", "p68", "p71", "p72", "p73", "p74", "p75", "p76", "p77", "p80", "p81", "p82", "p85", "p87", "p88", "p89", "p91", "p92", "p94", "p95", "p98", "p99", "p100", "p101", "p106", "p107", "p108", "p109", "p110", "p111", "p112", "p114", "p123", "p127"]:   # ★ 18.11: + p123, p127 (мост админ-центра)
            # ★ 22.10.2026: предел verify 900 → 1800 с (ASDA_VERIFY_TIMEOUT): verify_ac0 на загруженной машине шёл 742 с один
            #   и >900 с в пуле (раньше 570–620 с) — ловил ложный TIMEOUT
            add("verify", "verify_" + v, [py, os.path.join(st, "verify_%s.py" % v)], st,
                timeout=int(os.environ.get("ASDA_VERIFY_TIMEOUT", "1800")))
        add("verify", "stand_tick_locks", [py, os.path.join(st, "stand_tick_locks.py")], st, key="tick_locks")
        add("verify", "verify_traffic", [py, os.path.join(T, "AsdaSecure", "tools", "verify_traffic.py")], os.path.join(T, "AsdaSecure", "tools"))
        add("verify", "verify_sites", [py, os.path.join(T, "AsdaSecure", "tools", "verify_sites.py")], os.path.join(T, "AsdaSecure", "tools"))
        for v in ["n16", "n17", "n18", "n19", "n20", "n21", "n22", "n24"]:   # ★ 31.10.2026: + n21 (не было в списке), n22 (bug-quest-follow: ячейки NPC сверх 10)
               # ★ NpcServer (AddonNPC/tools; образы — по умолчанию с шары); n19 — 25.10.2026 (слот P86); n20 — 26.10.2026 (слот P90: N10 ред. 2 + N20)
            p = os.path.join(T, "AddonNPC", "tools", "verify_%s.py" % v)
            if os.path.exists(p):
                add("verify", "verify_" + v, [py, p], os.path.join(T, "AddonNPC", "tools"))
        # ★ 31.10.2026 (bug-quest-follow): стенд N22 — эмуляция площадок Process_Quest/Start_Quest (Unicorn), сток против патча.
        add("verify", "stand_n22", [py, os.path.join(T, "AddonNPC", "tools", "stand_n22.py")], os.path.join(T, "AddonNPC", "tools"))
        # ★ 31.10.2026: стенд загрузки таблицы N22 (x86, образ NpcServer + LoadLibrary AddonNPC, 12 случаев таблицы).
        add("verify", "stand_n22_load", [py, os.path.join(T, "AddonNPC", "tools", "stand_n22_load.py")], os.path.join(T, "AddonNPC", "tools"))
        # ★ 31.10.2026 (fix-check-started): общий разбор журнала патчей patchlog.judge — синтетика «второй старт за день с провалом».
        add("verify", "test_patchlog", [py, os.path.join(st, "test_patchlog.py")], st)
        # ★ 07.11.2026 (баг 9): шаг 3а restart_stack «штатное завершение GameServer» — логика ожидания и сценарий SC_CLOSE с подменённым SSH.
        add("verify", "test_graceful_stop", [py, os.path.join(st, "test_graceful_stop.py")], st)
    # ── AsdaSecure (стенды без общих папок → параллельно) ──
    if want("secure"):
        o = os.path.join(T, "AsdaSecure", "out")
        for s in ["stand_secure", "stand_wire", "stand_nocng"]:
            add("secure", s, [os.path.join(o, s + ".exe")], o)
        add("secure", "stand_b7d_locks", [os.path.join(o, "stand_b7d_locks.exe"), "all"], o)
        if os.path.exists(os.path.join(o, "stand_limit4096.exe")):
            add("secure", "stand_limit4096", [os.path.join(o, "stand_limit4096.exe")], o)
            add("secure", "stand_limit4096_old_expect_fail", [os.path.join(o, "stand_limit4096_old.exe")], o)
        if os.path.exists(os.path.join(o, "stand_backlog.exe")):
            add("secure", "stand_backlog", [os.path.join(o, "stand_backlog.exe")], o)
            add("secure", "stand_backlog_old_expect_fail", [os.path.join(o, "stand_backlog_old.exe")], o)
        if os.path.exists(os.path.join(o, "stand_rev4_on_fix2e.exe")):
            add("secure", "stand_rev4_fix2c_on_fix2e", [os.path.join(o, "stand_rev4_on_fix2e.exe")], o)
            add("secure", "stand_rev4_fix2d_on_fix2e", [os.path.join(o, "stand_rev4_fix2d_on_fix2e.exe")], o)
        elif os.path.exists(os.path.join(o, "stand_rev4_on_fix2d.exe")):
            add("secure", "stand_rev4_fix2c_on_fix2d", [os.path.join(o, "stand_rev4_on_fix2d.exe")], o)
        # ★ EAC ред. 3 (16.10.2026): экспортёр привязки канала (bind == Python-вектор, клиент == сервер, мост P61) и ключи
        #   направлений против фикстуры прежнего кода (stand\old_red2) — обязаны совпасть
        for s in ("stand_bind", "stand_bind_keys_old"):
            if os.path.exists(os.path.join(o, s + ".exe")):
                add("secure", s, [os.path.join(o, s + ".exe")], o)
    # ── стенды GS (замок = папка стенда) ──
    if want("gs"):
        for img, path in GS.items():
            add("stands", "p55_" + img, [E("p55"), path, DLL["gs"]], C("p55"), key=C("p55"))
            add("stands", "p64_" + img, [E("p64"), path, DLL["gs"]], C("p64"), key=C("p64"))
            add("stands", "ac0_gs_" + img, [E("ac0"), "gs", path, DLL["gs"]], C("ac0"), key=C("ac0"))
            for m in ("0", "1"):
                for n in ("p57", "p60", "p62", "p65", "p66", "p67", "p68"):
                    add("stands", "%s_%s_m%s" % (n, img, m), [E(n), path, DLL["gs"], m], C(n), key=C(n))
                for v in ("p63", "both", "rev", "p62"):
                    add("stands", "p63_%s_%s_m%s" % (v, img, m), [E("p63"), path, DLL["gs"], m, v], C("p63"), key=C("p63"))
                add("stands", "p56_gs_%s_m%s" % (img, m), [E("p56"), "gs", path, DLL["gs"], m], C("p56"), key=C("p56"))
                add("stands", "a5b_gs_%s_m%s" % (img, m), [E("a5b"), "gs", path, DLL["gs"], m], C("a5b"), key=C("a5b"))
            # ★ sec2c (15.10.2026): стенды P69 (autoban) и P48s (атрибуция кика P47/P48/P49/P55, Н-3/Н-4/Н-5) — прежде шли только
            #   раннерами волн (wSEC2b_logs/run_checks.py), в параллельном раннере их не было. Режимы задаёт сам стенд.
            for n in ("p69", "p48s"):
                if os.path.exists(E(n)):
                    add("stands", "%s_%s" % (n, img), [E(n), path, DLL["gs"]], C(n), key=C(n))
            # ★ p71p72n18: стенды P71 (только сток) и P72 ×5 режимов
            if os.path.exists(E("p72")):
                for m in ("on", "stock", "block", "off", "mismatch"):
                    add("stands", "p72_%s_%s" % (img, m), [E("p72"), path, DLL["gs"], m], C("p72"), key=C("p72"))
        # ★ P73 (мост EAC, 16.10.2026): стенд в AP/stand (кодек, очередь KICK, площадки, фальшивый сайдкар по TCP) — 3 образа × 5 режимов
        s73 = os.path.join(AP, "stand", "stand_p73.exe")
        if os.path.exists(s73):
            for img, path in GS.items():
                for m in ("unit", "journal", "chain", "mismatch", "tcp"):
                    add("stands", "p73_%s_%s" % (img, m), [s73, path, DLL["gs_stand"], m, "15799", py], os.path.dirname(s73), key=os.path.dirname(s73))
        # ★ P127 (мост админ-центра, 18.11.2026): общая точка UserTick, события P73 → P127, команды/подпись/сроки — 3 образа × 4 режима
        if os.path.exists(E("p127")):
            for img, path in GS.items():
                # ★ ревизия 24: + exec48 / exec48off (P48 и P53 ставятся ДО P127, как на живой стойке), nop123 (без P123)
                for m in ("exec", "exec48", "exec48off", "nop123", "noplus", "p75off", "listen", "off", "mismatch"):   # ★ А2.2: + noplus; ревизия 25: + p75off
                    add("stands", "p127_%s_%s" % (img, m), [E("p127"), path, DLL["gs_stand"], m], C("p127"), key=C("p127"))
        # ★ P74 (синхронизация боя Ф3, 17.10.2026): стенд HP 4058 соседям — 3 образа × 4 режима (ред. 2: + throttle)
        if os.path.exists(E("p74")):
            for img, path in GS.items():
                for m in ("on", "throttle", "off", "mismatch"):
                    add("stands", "p74_%s_%s" % (img, m), [E("p74"), path, DLL["gs"], m], C("p74"), key=C("p74"))
        # ★ P108 (выход из данжа в точку входа, 05.11.2026): площадка DisConnectUser 0x5257A0 с кадром, настоящие MapInfo.txt и
        #   PortalConfig стойки (stand_p108\data) — 3 образа × 4 режима
        if os.path.exists(E("p108")):
            for img, path in GS.items():
                for m in ("on", "custom", "off", "mismatch"):
                    add("stands", "p108_%s_%s" % (img, m), [E("p108"), path, DLL["gs"], m, os.path.join(C("p108"), "data")], C("p108"), key=C("p108"))
        # ★ P110 (пулы очков навыков, 05.11.2026, сессия job4-points): площадка Recv_SkillPoint_SkillActive 0x4778B3 с кадром, настоящий
        #   SkillInfo.sif стойки (stand_p110\data) — 3 образа × 5 режимов
        if os.path.exists(E("p110")):
            for img, path in GS.items():
                for m in ("on", "custom", "journal", "off", "mismatch"):
                    add("stands", "p110_%s_%s" % (img, m), [E("p110"), path, DLL["gs"], m, os.path.join(C("p110"), "data")], C("p110"), key=C("p110"))
        # ★ P111 (добавка вылупления, 05.11.2026, сессия pet-hatch-summon): НАСТОЯЩАЯ формула Recv_IncubatorReq 0x4556C3…0x455728 с кадром,
        #   настоящие подтипы и значения Function_Table/item_table стойки — 3 образа × 5 режимов
        if os.path.exists(E("p111")):
            for img, path in GS.items():
                for m in ("on", "custom", "journal", "off", "mismatch"):
                    add("stands", "p111_%s_%s" % (img, m), [E("p111"), path, DLL["gs"], m, os.path.join(C("p111"), "data")], C("p111"), key=C("p111"))
        # ★ P112 (разброс отряда в опыте, 06.11.2026): НАСТОЯЩИЙ sub_4C7650 — 3 образа × 6 режимов
        if os.path.exists(E("p112")):
            for img, path in GS.items():
                for m in ("on", "packet", "nofix", "journal", "off", "mismatch"):
                    add("stands", "p112_%s_%s" % (img, m), [E("p112"), path, DLL["gs"], m], C("p112"), key=C("p112"))
        # ★ P114 (опыт заданий доски, 07.11.2026): НАСТОЯЩИЕ площадка 0x53C4F9, GetExpUpDownValue и sub_4C6F80 — 3 образа × 3 режима
        if os.path.exists(E("p114")):
            for img, path in GS.items():
                for m in ("on", "off", "mismatch"):
                    add("stands", "p114_%s_%s" % (img, m), [E("p114"), path, DLL["gs"], m], C("p114"), key=C("p114"))
        # ★ P109 (навык на себя не бьёт кастера, 05.11.2026): НАСТОЯЩИЙ вход sub_470DB0 (ответ 8206) с пакетами живой раскладки
        #   5257 Player5 — 3 образа × 3 режима
        if os.path.exists(E("p109")):
            for img, path in GS.items():
                for m in ("on", "off", "mismatch"):
                    add("stands", "p109_%s_%s" % (img, m), [E("p109"), path, DLL["gs"], m], C("p109"), key=C("p109"))
        # ★ P75 (зелье повышения уровня 558, 19.10.2026): шаги 1/2 на настоящем коде + НАСТОЯЩИЙ Recv_BattleServerFromCharParamExp_1,
        #   ExpTable стойки — 3 образа × 5 режимов
        if os.path.exists(E("p75")):
            for img, path in GS.items():
                for m in ("on", "p63", "stock", "nop29", "off", "mismatch"):
                    add("stands", "p75_%s_%s" % (img, m), [E("p75"), path, DLL["gs"], m], C("p75"), key=C("p75"))
        # ★ P76 (поля пакетов живых камней 5022/5024/5031, 21.10.2026): стабы на образе + заглушка sub_52BFF0 — 3 образа × 4 режима
        if os.path.exists(E("p76")):
            for img, path in GS.items():
                for m in ("1", "0", "off", "mismatch"):
                    add("stands", "p76_%s_%s" % (img, m), [E("p76"), path, DLL["gs"], m], C("p76"), key=C("p76"))
        # ★ P77 (4009 в точку сервера при молчаливой остановке хода, 22.10.2026): НАСТОЯЩИЕ MoveSyncProcess + CharMove — 3 образа × 4 режима
        if os.path.exists(E("p77")):
            for img, path in GS.items():
                for m in ("on", "self", "off", "mismatch"):
                    add("stands", "p77_%s_%s" % (img, m), [E("p77"), path, DLL["gs"], m], C("p77"), key=C("p77"))
        # ★ P80 (ход вприсядку ×0.5 и прыжок с бега соседям, 24.10.2026): НАСТОЯЩИЕ RecalcMoveSpeed + CharMove + CharEMotionSync —
        #   3 образа × 5 режимов
        if os.path.exists(E("p80")):
            for img, path in GS.items():
                for m in ("on", "nocrouch", "norelay", "off", "mismatch"):
                    add("stands", "p80_%s_%s" % (img, m), [E("p80"), path, DLL["gs"], m], C("p80"), key=C("p80"))
        # ★ P81 (страж кода 4024 и частоты «Dancer», 24.10.2026): НАСТОЯЩИЙ CharEMotionSync + P80 S2 + журнал P53 — 3 образа × 8 режимов
        if os.path.exists(E("p81")):
            for img, path in GS.items():
                for m in ("on", "journal", "nop80", "no131", "nodance", "dance1", "off", "mismatch"):
                    add("stands", "p81_%s_%s" % (img, m), [E("p81"), path, DLL["gs"], m], C("p81"), key=C("p81"))
        # ★ P82 (откат функциональных предметов с кодом >= 600, 24.10.2026): НАСТОЯЩИЕ sub_4F27F0/sub_4F2640, циклы восстановления
        #   входа/портала, хвост сохранения 2157, такт TimerProcess, ClearUserMemory, 5450/2141 (и через P75) — 3 образа × 6 режимов
        if os.path.exists(E("p82")):
            for img, path in GS.items():
                for m in ("on", "guard", "nosave", "p75", "off", "mismatch"):
                    add("stands", "p82_%s_%s" % (img, m), [E("p82"), path, DLL["gs"], m], C("p82"), key=C("p82"))
        # ★ P85 (премиум-корзина целиком, 25.10.2026): НАСТОЯЩАЯ ветка 137 sub_4F60E0 — расширение корзины в запросе шлюзу gp7
        if os.path.exists(E("p85")):
            for img, path in GS.items():
                for m in ("on", "off", "mismatch"):
                    add("stands", "p85_gs_%s_%s" % (img, m), [E("p85"), "gs", path, DLL["gs"], m], C("p85"), key=C("p85"))
        # ★ P87 (стартовые навыки 4-й профессии по подклассу, 26.10.2026): НАСТОЯЩИЙ sub_481CE0 (switch по подклассу, гейт очков,
        #   LABEL_99) + вход прямо на LABEL_99; таблица строк ChangeJobAddSkillTable стойки (сток — из Donors) — 3 образа × 3 режима
        if os.path.exists(E("p87")):
            tabs = {"stock": r"@@ASTORY_DEV_ROOT@@\Donors\GameServer_stock\SkillTable_Info\ChangeJobAddSkillTable.txt",
                    "live": SHARE + "/v2/GameServer/SkillTable_Info/ChangeJobAddSkillTable.txt",
                    "indun": SHARE + "/v2/Indun_GameServer/SkillTable_Info/ChangeJobAddSkillTable.txt"}
            for img, path in GS.items():
                for m in ("on", "off", "mismatch"):
                    add("stands", "p87_%s_%s" % (img, m), [E("p87"), path, DLL["gs"], m, tabs[img].replace("/", "\\")], C("p87"), key=C("p87"))
        # ★ P88 (события званий 187–205, 26.10.2026): площадки A/B1/B2/C/D/E/G с поддельным кадром обработчика и ловушкой на адресе
        #   возврата, переходник F; FameInfo и файлы грейдов — staging AstoryServer/Docs/titles_p88_1026 — 3 образа × 3 режима
        if os.path.exists(E("p88")):
            for img, path in GS.items():
                for m in ("on", "off", "mismatch"):
                    add("stands", "p88_%s_%s" % (img, m), [E("p88"), path, DLL["gs"], m], C("p88"), key=C("p88"))
        # ★ P89 (гейт стартовых навыков 4-й профессии по ветке, 26.10.2026): НАСТОЯЩИЕ sub_47E9B0 / sub_481CE0 / sub_48A8C0 /
        #   sub_475650 вместе с P87; staging ChangeJobAddSkillTable (AstoryServer/Docs/job4_start_skills_1026, строки 6/17/28) и
        #   SkillInfo.sif стойки — 3 образа × 5 режимов (off = живая стойка до P89: дефект у лучника/мага воспроизводится)
        if os.path.exists(E("p89")):
            tab89 = os.path.normpath(os.path.join(AP, "..", "..", "Docs", "job4_start_skills_1026", "GameServer", "SkillTable_Info",
                                                  "ChangeJobAddSkillTable.txt"))
            sif89 = (SHARE + "/v2/GameServer/SkillTable_Info/SkillInfo.sif").replace("/", "\\")
            for img, path in GS.items():
                for m in ("on", "noskip", "log", "off", "mismatch"):
                    add("stands", "p89_%s_%s" % (img, m), [E("p89"), path, DLL["gs"], m, tab89, sif89], C("p89"), key=C("p89"))
        # ★ P91 (потолок опыта за моба × рейт события, 26.10.2026, волна exprate): НАСТОЯЩИЕ фрагменты 0x4CBBEF…0x4CBC7E и
        #   0x4C7FFE…0x4C8093, матрица рейтов x1…x5 × уровни 1–10/50/70/99, сверка со стоковым прогоном; ExpTable — в папке стенда
        if os.path.exists(E("p91")):
            tab91 = os.path.join(C("p91"), "ExpTable.txt")
            for img, path in GS.items():
                for m in ("on", "stock", "div5", "off", "mismatch", "nosolo"):
                    add("stands", "p91_%s_%s" % (img, m), [E("p91"), path, DLL["gs"], m, tab91], C("p91"), key=C("p91"))
        # ★ P92 (вредный эффект навыка — только на враждебного игрока, 26.10.2026, волна bowfx): НАСТОЯЩИЕ sub_556DB0 (через P42 C1),
        #   EXPLOSION_ARROW / GUARDIAN_NORMAL_ATTACK_AREA / GUARDIAN_DAMAGE_REPLEX, sub_4283F0 (как из 8009 и внутренний), цикл целей
        #   5256; матрица отношений (мирный, PvP, дуэль, осада, свободный бой клан/Друг/отряд/чужой, моб) — фаза A сток, фаза B режим;
        #   SkillInfo.sif стойки — 3 образа × 5 режимов
        if os.path.exists(E("p92")):
            sif92 = (SHARE + "/v2/GameServer/SkillTable_Info/SkillInfo.sif").replace("/", "\\")
            for img, path in GS.items():
                for m in ("on", "throttle", "journal", "off", "mismatch"):
                    add("stands", "p92_%s_%s" % (img, m), [E("p92"), path, DLL["gs"], m, sif92], C("p92"), key=C("p92"))
        # ★ P94 (сообщения пары — не себе и не чужой паре, 26.10.2026, волна charpos): НАСТОЯЩИЕ обработчики relay recv_1 /
        #   recvSoulMateStateInfo / sub_4949C0 / sub_494010 целиком, 7 сценариев (Друг, «себе», по учётке, другой канал, чужая
        #   пара, без пары, пустой слот) — сток до установки и после, 3 образа × 5 режимов
        if os.path.exists(E("p94")):
            for img, path in GS.items():
                for m in ("on", "journal", "noforeign", "off", "mismatch"):
                    add("stands", "p94_%s_%s" % (img, m), [E("p94"), path, DLL["gs"], m], C("p94"), key=C("p94"))
        # ★ P95 (коробки 6096 — раскладка по правилу сервера и мин. уровень; бустер 5468 и расходник 5028 — мин. уровень, 29.10.2026,
        #   волна bugs6): НАСТОЯЩИЕ Recv_OpenPackageItem / Recv_GachaItemUse / CharSpendItemUse целиком на НАСТОЯЩИХ таблицах стойки
        #   (item_table.txt, PackageItem_Table.txt зеркала), 15 сценариев (Cancer Star Set 75662, стопки, затирание, «нет места»,
        #   дубли, уровни) — сток до установки и после, 3 образа × 5 режимов
        if os.path.exists(E("p95")):
            tab95 = (SHARE + "/v2/GameServer/ItemTable_Info").replace("/", "\\")
            for img, path in GS.items():
                for m in ("on", "noplace", "nolevel", "off", "mismatch"):
                    add("stands", "p95_%s_%s" % (img, m), [E("p95"), path, DLL["gs"], m, tab95], C("p95"), key=C("p95"))
        # ★ P98 (премиум-почта 11006: стопочный предмет приходит 1 шт., 30.10.2026, волна bugs7): НАСТОЯЩИЕ Recv_PremiumItemToInven_Req
        #   и ответ БД sub_4F89D0 целиком на НАСТОЯЩЕЙ item_table зеркала, 7 сценариев (новая стопка, стопка N — дюп, стопка из 1,
        #   нестопочный, колчан, экипировка) + путь P16 — сток до установки и после, 3 образа × 5 режимов (full — вместе с P96/P97)
        if os.path.exists(E("p98")):
            tab98 = (SHARE + "/v2/GameServer/ItemTable_Info").replace("/", "\\")
            for img, path in GS.items():
                for m in ("on", "journal", "full", "off", "mismatch"):
                    add("stands", "p98_%s_%s" % (img, m), [E("p98"), path, DLL["gs"], m, tab98], C("p98"), key=C("p98"))
        # ★ P100 (заряды спецпредметов складываются при получении, 01.11.2026): НАСТОЯЩИЕ обработчики 11006/2604, GM 6042, 6096/2273
        #   (через P95), склад 5010/2032, аукцион 9906/2205 (откат), гача 5468/2229, разборка 6502/2302, война роз sub_469010/sub_469A00,
        #   ответы сундука/книги рыбака/событий, аукцион снятие 9910/2207, площадки с кадром B1/B3/B4/A5/B6, sub_5340B0 «из» путей
        #   ABS/ADD/шаблон, P16-экспорт, P62 (Mode=0) на 6096; поверх P53+P62+P96+P97+P95+P98 —
        #   сток до установки и после, 3 образа × 4 режима. FT и charge_groups — в папку стенда (их сверяет DLL по ft_md5)
        if os.path.exists(E("p100")):
            tab100 = (SHARE + "/v2/GameServer/ItemTable_Info").replace("/", "\\")
            cg100 = os.path.join(st, "p100_data", "charge_groups.txt")
            for img, path in GS.items():
                # ★ 05.11.2026 (v62): echooff — P100 стоит, EchoAllCodes=0 (ответ 2604 по-старому; сценарий A1-эхо воспроизводит дефект)
                for m in ("on", "off", "mismatch", "journal", "echooff"):
                    add("stands", "p100_%s_%s" % (img, m), [E("p100"), path, DLL["gs"], m, tab100, cg100], C("p100"), key=C("p100"))
                # ★ 19.11.2026 P127 А2.3: стендовая DLL — выдача моста (перенос хвоста 0x552360) побайтно = настоящий обработчик 6042
                for m in ("on", "off"):
                    add("stands", "p100p127_%s_%s" % (img, m), [E("p100"), path, DLL["gs_stand"], m, tab100, cg100], C("p100"), key=C("p100"))
        # ★ P101 (подарок из кэш-магазина, 02.11.2026): НАСТОЯЩИЕ диспетчер клиента (площадка 0x42AD02, кадр диспетчера), цепочка
        #   шлюза 0x42FC3B, call-площадки 0x4303DE/0x430412/0x430446/0x43047A, получатель recvChatResponse…Gift и sub_513910 целиком;
        #   петля 5072→2132→2133→5073→5074→0x52→0x53→5076→2134→2135→5078/5077→settle→5075 на таблицах зеркала (item_table, FT,
        #   SellItemTable) поверх P53+P96+P97+P100 — 3 образа × 9 режимов (маска по битам, без P100, порча площадки, DLL раньше таблиц)
        if os.path.exists(E("p101")):
            tab101 = (SHARE + "/v2/GameServer/ItemTable_Info").replace("/", "\\")
            cg101 = os.path.join(st, "p100_data", "charge_groups.txt")
            for img, path in GS.items():
                for m in ("on", "off", "s1", "s2", "s4", "s8", "nop100", "mismatch", "early"):
                    add("stands", "p101_%s_%s" % (img, m), [E("p101"), path, DLL["gs"], m, tab101, cg101], C("p101"), key=C("p101"))
        if os.path.exists(E("p71")):
            for m in ("on", "partial", "off", "mismatch"):
                add("stands", "p71_stock_" + m, [E("p71"), GS["stock"], DLL["gs"], m], C("p71"), key=C("p71"))
    # ── стенды NPC и DB ──
    if want("npc"):
        npc_imgs = {}
        for img, src in NPC_SRC.items():
            path = os.path.join(tmp, "npc_%s.exe" % img); shutil.copyfile(src, path); npc_imgs[img] = path
            add("stands", "p56_npc_" + img, [E("p56"), "npc", path, DLL["npc"]], C("p56"), key=C("p56"))
            add("stands", "a5b_npc_%s_m0s20" % img, [E("a5b"), "npc", path, DLL["npc"], "0", "20"], C("a5b"), key=C("a5b"))
            add("stands", "a5b_npc_%s_m1s5" % img, [E("a5b"), "npc", path, DLL["npc"], "1", "5"], C("a5b"), key=C("a5b"))
        nst = os.path.join(T, "AddonNPC", "tools")
        for n in ("n17", "n18", "n19", "n20"):   # ★ стенды N17/N18/N19/N20 (AddonNPC/tools), 3 образа; n20 — 26.10.2026 (слот P90)
            exe = os.path.join(nst, "stand_" + n, "stand_%s.exe" % n)
            if os.path.exists(exe):
                modes = {"n17": ("on", "off", "mismatch", "all"), "n18": ("on", "off", "mismatch", "grp", "all"),
                         "n19": ("on", "on0", "journal", "off", "mismatch", "pvpoff", "all"),
                         "n20": ("on", "nocrit", "noneg", "off", "mismatch", "all")}[n]
                for img, path in npc_imgs.items():
                    for m in modes:
                        add("stands", "%s_%s_%s" % (n, img, m), [exe, path, DLL["npc"], m], os.path.dirname(exe), key=os.path.dirname(exe))
        # ★ N24 (нет лута с низких мобов, 06.11.2026): НАСТОЯЩИЙ Process_MonsterDead на всех образах NpcServer + настоящий sub_4C7650 (опыт отряда)
        n24 = os.path.join(nst, "stand_n24", "stand_n24.exe")
        if os.path.exists(n24):
            for img, path in npc_imgs.items():
                for m in ("on", "custom", "journal", "off", "mismatch", "range0"):   # range0 — SpreadRangeTiles=0 (09.11.2026)
                    add("stands", "n24_%s_%s" % (img, m), [n24, path, DLL["npc"], m], os.path.dirname(n24), key=os.path.dirname(n24))
            for img, path in GS.items():
                add("stands", "n24_gsexp_" + img, [n24, path, DLL["npc"], "gsexp"], os.path.dirname(n24), key=os.path.dirname(n24))
        dbm = os.path.join(tmp, "dbm_live.exe"); shutil.copyfile(DBM_SRC, dbm)
        add("stands", "ac0_db_live", [E("ac0"), "db", dbm, DLL["db"]], C("ac0"), key=C("ac0"))
        if os.path.exists(E("p85")):   # ★ P85 DbPostRows (25.10.2026): площадка 0x43F0DC — потолок списка ящика 490 б
            for m in ("on", "off", "mismatch"):
                add("stands", "p85_db_live_" + m, [E("p85"), "db", dbm, DLL["db"], m], C("p85"), key=C("p85"))
    # ── stand_map ──
    if want("map"):
        src = os.path.join(st, "stand_map", "stand_map.exe")
        for img, path in GS.items():
            add("stands", "stand_map_" + img, [src, path, DLL["gs"]], os.path.dirname(src), key=os.path.dirname(src))
        smap = os.path.join(tmp, "smap"); os.makedirs(smap, exist_ok=True)
        shutil.copyfile(src, os.path.join(smap, "stand_map.exe"))
        cs = os.path.join(os.path.dirname(src), "ConfigSet")
        if os.path.isdir(cs):
            shutil.copytree(cs, os.path.join(smap, "ConfigSet"), ignore=shutil.ignore_patterns("patches.ini*"))
        md = os.path.join(os.path.dirname(src), "MapData_Info")    # ★ 04.11.2026: P30 читает MapInfo.txt / MapWarpCost.txt (иначе не ставится)
        if os.path.isdir(md):
            shutil.copytree(md, os.path.join(smap, "MapData_Info"), dirs_exist_ok=True)
        it = os.path.join(os.path.dirname(src), "ItemTable_Info")   # ★ P100 (01.11.2026): FT для сверки ft_md5 charge_groups.txt
        if os.path.isdir(it):
            shutil.copytree(it, os.path.join(smap, "ItemTable_Info"), dirs_exist_ok=True)
        kg = os.path.join(T, "AsdaSecure", "out", "keygen.exe")
        subprocess.run([kg, os.path.join(smap, "secure_server.key"), os.path.join(tmp, "test_pub.h")], capture_output=True)
        for img, path in GS.items():
            add("stands", "stand_map_%s_all" % img, [os.path.join(smap, "stand_map.exe"), path, DLL["gs"],
                "P61_TrafficEncryption=Enabled=1", "P08_FunctionItemUseCheckOff=Enabled=1", "P31_PetUnionRemoveNotify=Enabled=1"], smap, key=smap)
    # ── журнал ──
    if want("acj"):
        d = os.path.join(st, "stand_acjournal")
        for m in ("down", "flood", "filerows", "filecap"):
            add("stands", "acjournal_" + m, [os.path.join(d, "stand_acjournal.exe"), m, "REGRESS-" + m], d, key=d)
    # ── LoginPatch ──
    if want("lm"):
        lp = os.path.join(T, "LoginPatch")
        for t in ("test_l01", "test_l23", "test_l04", "test_l04c", "test_l06"):
            add("lm", t, [os.path.join(lp, "obj", t + ".exe")], lp, key=lp)
        add("lm", "host_load", [os.path.join(lp, "obj", "host_load.exe"), DLL["lm"]], lp, key=lp)
        # ★ 27.10.2026 L08: стенд на живом образе LoginManager (51db86b2), 5 режимов; сборка — LoginPatch\tools\regress_all.bat
        sl = os.path.join(lp, "tools", "stand_l08")
        for m in ("on", "off", "parts", "mismatch", "all"):
            add("lm", "stand_l08_" + m, [os.path.join(sl, "stand_l08.exe"), os.path.join(lp, "out", "LoginManager.exe.loginpatch.exe"),
                                         DLL["lm"], m], sl, key=sl)

    # ── исполнение: долгие verify первыми (длинный хвост не задерживает конец) ──
    t0 = time.time()
    order = sorted(range(len(JOBS)), key=lambda i: 0 if JOBS[i][0] == "verify" else 1)
    with ThreadPoolExecutor(max_workers=jobs_n) as ex:
        list(ex.map(execute, order))
    total = time.time() - t0
    # ── сводка в исходном порядке ──
    with open(os.path.join(HERE, "summary%s.txt" % ("_" + only if only else "")), "w", encoding="utf-8", newline="\n") as f:
        f.write("DLL md5: %s\n" % {k: md5(v) for k, v in DLL.items()})
        tok = tbad = 0
        for i in range(len(JOBS)):
            g, n, rc, ok, bad, tail, sec = RESULTS[i]
            f.write("%-8s %-30s rc=%-3d OK=%-5d bad=%-3d %5.0fs %s\n" % (g, n, rc, ok, bad, sec, tail))
            tok += ok; tbad += bad
        if SKIPPED:
            f.write("ПРОПУЩЕНО ключом ASDA_SKIP_JOBS (%d): %s\n" % (len(SKIPPED), ", ".join(SKIPPED)))
        f.write("ВСЕГО прогонов %d, [OK] %d, провалов-меток %d, rc!=0: %s; время %.0f с, воркеров %d\n" % (
            len(JOBS), tok, tbad, [RESULTS[i][1] for i in range(len(JOBS)) if RESULTS[i][2] != 0], total, jobs_n))
    print("ВСЕГО прогонов %d, [OK] %d, провалов-меток %d, rc!=0: %s; время %.0f с" % (
        len(JOBS), sum(r[3] for r in RESULTS.values()), sum(r[4] for r in RESULTS.values()),
        [RESULTS[i][1] for i in range(len(JOBS)) if RESULTS[i][2] != 0], total))
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
