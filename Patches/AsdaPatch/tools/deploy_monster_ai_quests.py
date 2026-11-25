# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_monster_ai_quests.py — ВЫКЛАДКА / ОТКАТ Monster.ai: зачёт заданий только за их цель (решение владельца 06.11.2026).
#
# Изменение ДАННЫХ ОРИГИНАЛА, код сервера не меняется. Отчёт: Reports/quest_mobs/QUEST_STRAY_CREDIT.md;
#   генератор и список записей: monster_ai_quests_data.py (64 записи убрано, 5 добавлено, у King Spade стадия 398: 1 → 0).
# Шесть копий: GameServer\MonsterData_Info и NpcServer\Monster (поле, Indun, канал 2). Базы две; Indun_GameServer получает
#   свой новый файл и сохраняет свои отличия.
# NpcServer и GameServer читают файл на старте, поэтому выкладка — при остановленной стойке:
#   python restart_stack.py --deploy deploy_monster_ai_quests.py
# Сухой прогон (по умолчанию): только чтение по SSH, сверка md5 базы всех копий и локальных файлов.
# --apply (стойка остановлена): сверка базы (чужой md5 — СТОП, ничего не тронуто) → бэкап (рядом <файл>.bak_20261106_monsterai,
#   v2\_backup\2026-11-06_monster_ai_quests, @@ASTORY_DEV_ROOT@@\_backup\2026-11-06_monster_ai_quests\server\v2) → stage со сверкой →
#   копия на место со сверкой → «ГОТОВО». Уже новый файл пропускается.
# --rollback (стойка остановлена): файлы, равные новому, — из <файл>.bak_20261106_monsterai со сверкой md5 базы.
# Журнал: run_monster_ai_quests_20261106/deploy.log.
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                                         # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import ps, q, md5                                           # общие функции SSH (без побочных эффектов)
import monster_ai_quests_data as data                                       # базы и сверка пары файлов

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                                             # корень стойки
DATA = data.DATA                                                            # база и новые файлы
SUFFIX = ".bak_20261106_monsterai"                                          # бэкап рядом с файлом
SRV_BACKUP = V2 + r"\_backup\2026-11-06_monster_ai_quests"                  # бэкап на сервере
STAGE = SRV_BACKUP + r"\stage"                                              # залитые новые файлы
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-06_monster_ai_quests/server/v2" # локальный бэкап
LOG = os.path.join(HERE, "run_monster_ai_quests_20261106", "deploy.log")    # журнал выкладки
BASE_MAIN = "42106585299fe4b1c8125a3cf54868dd"                              # база 5 копий
BASE_INDUN = "d09877a0be3ea6ea0f0e9e6cc35925b9"                             # база Indun_GameServer
NEW_MD5 = {BASE_MAIN: "2b7467939e6843e14f0e2d1220b4cdd4",                   # база → новый файл
           BASE_INDUN: "17d95b3accebbd130dea9d660b5a2643"}
BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS] + [d + r"\NpcServer.exe" for d in stack_layout.NPC_FOLDERS]   # процессы, читающие файл


def plan_files():
    """Путь от v2 → база этой копии."""
    out = {}
    for d in stack_layout.GS_FOLDERS:
        out[d + r"\MonsterData_Info\Monster.ai"] = BASE_INDUN if d == "Indun_GameServer" else BASE_MAIN
    for d in stack_layout.NPC_FOLDERS:
        out[d + r"\Monster\Monster.ai"] = BASE_MAIN
    return out


def local_new(base):
    """Локальный новый файл для базы."""
    return os.path.join(DATA, data.BASES[base] + ".new.ai")


def local_base(base):
    """Локальная копия базы."""
    return os.path.join(DATA, "base", data.BASES[base] + ".ai")


def log(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def ps_list(paths):
    """Литерал массива PowerShell из путей."""
    return "@(" + ",".join(q(p) for p in paths) + ")"


def md5_abs(paths):
    """md5 файлов сервера по абсолютным путям одним вызовом: {путь: md5 | 'none'}."""
    rc, out = ps("foreach ($p in %s) { Write-Output ('M|' + $p + '|' + (Md5Of $p)) }" % ps_list(paths), timeout=180)
    res = {l.split("|")[1]: l.split("|")[2].strip().lower() for l in out.splitlines() if l.startswith("M|") and l.count("|") == 2}
    if rc != 0 or len(res) != len(set(paths)):
        raise RuntimeError("md5 по SSH: код %d: %s" % (rc, out[-300:]))
    return res


def md5_rel(rels):
    """md5 файлов стойки по путям от v2."""
    res = md5_abs([V2 + "\\" + r for r in rels])
    return {r: res[V2 + "\\" + r] for r in rels}


def busy_list():
    """Занятые процессами файлы."""
    rc, out = ps("foreach ($r in %s) { Write-Output ('B|' + $r + '|' + (IsBusy (Join-Path %s $r))) }" % (ps_list(BUSY), q(V2)), timeout=120)
    if rc != 0:
        raise RuntimeError("занятость по SSH: код %d: %s" % (rc, out[-300:]))
    return [l.split("|")[1] for l in out.splitlines() if l.startswith("B|") and l.strip().endswith("BUSY")]


def check_local(lines):
    """Локальные файлы: md5 баз и новых, сверка пары генератором."""
    for base, new in NEW_MD5.items():
        if md5(local_base(base)) != base or md5(local_new(base)) != new:
            raise RuntimeError("локальный файл базы %s не сошёлся: запустите monster_ai_quests_data.py build" % base[:8])
        with open(local_base(base), "rb") as f, open(local_new(base), "rb") as g:
            bad = data.verify_pair(f.read(), g.read())
        if bad:
            raise RuntimeError("сверка пары %s: %s" % (base[:8], bad))
    log(lines, "  локальные файлы сошлись: %s" % ", ".join("%s → %s" % (b[:8], n[:8]) for b, n in NEW_MD5.items()))


def backup(todo, plan, lines):
    """Бэкап: рядом и в v2\\_backup со сверкой md5, локально из сверенной копии базы."""
    for rel in todo:
        src = V2 + "\\" + rel
        for dst in (src + SUFFIX, SRV_BACKUP + "\\" + rel):
            rc, out = ps("$d = Split-Path -Parent %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                         "if ((Md5Of %s) -eq 'none') { Copy-Item -LiteralPath %s -Destination %s }; Write-Output ('M|' + (Md5Of %s))" % (q(dst), q(dst), q(src), q(dst), q(dst)), timeout=120)
            got = [l[2:].strip() for l in out.splitlines() if l.startswith("M|")]
            if rc != 0 or not got or got[-1] != plan[rel]:
                raise RuntimeError("бэкап %s: %s" % (dst, out[-300:]))
        loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
        if os.path.exists(loc) and md5(loc) != plan[rel]:
            raise RuntimeError("локальный бэкап %s уже есть и это другой файл" % loc)
        if not os.path.exists(loc):
            os.makedirs(os.path.dirname(loc), exist_ok=True)
            with open(local_base(plan[rel]), "rb") as f, open(loc, "wb") as g:
                g.write(f.read())
        log(lines, "  бэкап: %s" % rel)


def upload(todo, plan, lines):
    """Новые файлы → stage по scp → сверка md5 → копия на место → сверка."""
    bases = sorted({plan[rel] for rel in todo})
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null; Write-Output OK" % q(STAGE))
    r = subprocess.run(["scp", "-q", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes"] + [local_new(b) for b in bases] +
                       ["Administrator@@@ASTORY_SERVER_VPN_IP@@:" + STAGE.replace("\\", "/") + "/"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("scp в stage: %s" % r.stderr.strip())
    staged = {b: STAGE + "\\" + data.BASES[b] + ".new.ai" for b in bases}
    st = md5_abs(list(staged.values()))
    for b, path in staged.items():
        if st[path] != NEW_MD5[b]:
            raise RuntimeError("stage %s = %s, ожидался %s: ничего не скопировано" % (path, st[path], NEW_MD5[b]))
    for rel in todo:
        rc, out = ps("Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output ('M|' + (Md5Of %s))" % (q(staged[plan[rel]]), q(V2 + "\\" + rel), q(V2 + "\\" + rel)), timeout=120)
        got = [l[2:].strip() for l in out.splitlines() if l.startswith("M|")]
        ok = rc == 0 and got and got[-1] == NEW_MD5[plan[rel]]
        log(lines, "  %s выложено: %s %s" % (rel, got[-1] if got else "?", "OK" if ok else "НЕ СОШЛОСЬ"))
        if not ok:
            raise RuntimeError("после копии %s: %s" % (rel, out[-300:]))


def rollback(plan, cur, lines):
    """Откат: файлы, равные новому, из бэкапа рядом; код возврата."""
    todo = [rel for rel, base in plan.items() if cur[rel] == NEW_MD5[base]]
    for rel, base in plan.items():
        if cur[rel] not in (base, NEW_MD5[base]):
            log(lines, "  ВНИМАНИЕ: %s = %s, не база и не новый: откат его не трогает" % (rel, cur[rel]))
    baks =md5_abs([V2 + "\\" + rel + SUFFIX for rel in todo]) if todo else {}
    for rel in todo:
        if baks[V2 + "\\" + rel + SUFFIX] != plan[rel]:
            log(lines, "СТОП: %s%s нет или это не база: ничего не тронуто" % (rel, SUFFIX))
            return 6
    for rel in todo:
        rc, out = ps("Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output ('M|' + (Md5Of %s))" % (q(V2 + "\\" + rel + SUFFIX), q(V2 + "\\" + rel), q(V2 + "\\" + rel)), timeout=120)
        got = [l[2:].strip() for l in out.splitlines() if l.startswith("M|")]
        ok = rc == 0 and got and got[-1] == plan[rel]
        log(lines, "  %s откат: %s %s" % (rel, got[-1] if got else "?", "OK" if ok else "НЕ СОШЛОСЬ"))
        if not ok:
            return 5
    log(lines, "ГОТОВО: откачено файлов %d, стойку можно запускать" % len(todo))
    return 0


def main():
    """Точка входа: сухой прогон, --apply, --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    apply = "--apply" in sys.argv
    undo = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_monster_ai_quests %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if undo else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        busy = busy_list()
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or undo):
            log(lines, "СТОП: стойка не остановлена: ничего не тронуто")
            flush(lines)
            return 2
        plan = plan_files()
        cur = md5_rel(list(plan))
        if undo:
            rc = rollback(plan, cur, lines)
            flush(lines)
            return rc
        check_local(lines)
        todo = []
        for rel, base in plan.items():
            state = "база" if cur[rel] == base else "уже новый" if cur[rel] == NEW_MD5[base] else "ЧУЖОЙ"
            log(lines, "  %s: %s (%s)" % (rel, cur[rel], state))
            if state == "ЧУЖОЙ":
                log(lines, "СТОП: md5 копии неожиданный: ничего не тронуто")
                flush(lines)
                return 3
            if state == "база":
                todo.append(rel)
        log(lines, "к выкладке: %d из %d" % (len(todo), len(plan)))
        if apply:
            backup(todo, plan, lines)
            if todo:
                upload(todo, plan, lines)
            log(lines, "ГОТОВО: выложено файлов %d" % len(todo))
        flush(lines)
        return 0
    except Exception as e:
        log(lines, "СТОП: %s" % e)
        flush(lines)
        return 1


if __name__ == "__main__":
    sys.exit(main())
