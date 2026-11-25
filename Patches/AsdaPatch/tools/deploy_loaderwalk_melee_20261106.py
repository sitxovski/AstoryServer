# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_loaderwalk_melee_20261106.py — ВЫКЛАДКА / ОТКАТ MonsterSkillCondition.mst: Loaderwalk чаще подходит вплотную.
#
# Решение владельца 06.11.2026. Изменение ДАННЫХ ОРИГИНАЛА, код сервера не меняется, номер патча не нужен.
#   Типы 289 «Тяжелонос» (로더웍) и 435 «Злобный тяжелонос» (매니악 로더웍): шанс условия 7 (навык 18) 100 → RATE.
#   Байт шанса = запись условия +11 (NpcServer: сравнение sub_408A60() с mon+33991, sub_4499B0). Прочие типы не тронуты.
#   Разбор и расчёт: Reports/mob_stationary/LOADERWALK_MELEE.md.
# Шесть копий: NpcServer\MonsterSkill и GameServer\SkillTable_Info (поле, Indun, канал 2), состав из stack_layout.
#   Папки NpcServer\Skill (другой файл fe6dd2d1) сервером не читаются, их скрипт не трогает.
# Файл читается на старте, поэтому выкладка — при остановленной стойке:
#   python restart_stack.py --deploy deploy_loaderwalk_melee_20261106.py
# Сухой прогон (по умолчанию): только чтение по SSH и сверка md5 всех копий, файлы сервера не меняются.
# --apply (стойка остановлена): сверка базы (чужой md5 — СТОП) → бэкап рядом, в v2\_backup и локально → stage со сверкой
#   → копия на место со сверкой. Уже новый файл пропускается.
# --rollback (стойка остановлена): файлы, равные новому, — из <файл>.bak_20261106_loaderwalk.
# --build: собрать новый файл из базы (локально).
# Журнал: run_loaderwalk_melee_20261106/deploy.log.
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout                                                         # единый состав стойки
from deploy_p90 import ps, q, md5                                           # общие функции SSH

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"                                             # корень стойки
NAME = "MonsterSkillCondition.mst"                                          # имя файла таблицы
DATA = os.path.normpath(os.path.join(HERE, "..", "..", "NpcData", "2026-11-06_loaderwalk_melee"))   # база и новый файл
LOCAL_BASE = os.path.join(DATA, "base", NAME)                               # сверенная копия базы
LOCAL_NEW = os.path.join(DATA, NAME)                                        # новый файл
SUFFIX = ".bak_20261106_loaderwalk"                                         # бэкап рядом с файлом
SRV_BACKUP = V2 + r"\_backup\2026-11-06_loaderwalk_melee"                   # бэкап на сервере
STAGE = SRV_BACKUP + r"\stage"                                              # залитый новый файл
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-06_loaderwalk_melee/server/v2"  # локальный бэкап
LOG = os.path.join(HERE, "run_loaderwalk_melee_20261106", "deploy.log")     # журнал выкладки
BASE_MD5 = "7297cf09b8a5bd1daa09ac2371a2d1b1"                               # база всех шести копий
NEW_MD5 = "416985be5af26eb18a2f5a1bdfcfbc62"                                                     # новый файл
REC = 386                                                                   # размер записи типа
OLD_RATE = 100                                                              # шанс в базе
RATE = 60                                                                   # новый шанс условия 7
RATE_OFFSETS = {289: 111259, 435: 167615}                                   # тип → смещение байта шанса
BUSY = [d + r"\GameServer.exe" for d in stack_layout.GS_FOLDERS] + [d + r"\NpcServer.exe" for d in stack_layout.NPC_FOLDERS]   # признак работающей стойки


def plan_files():
    """Пути копий от v2."""
    return ([d + "\\SkillTable_Info\\" + NAME for d in stack_layout.GS_FOLDERS] +
            [d + "\\MonsterSkill\\" + NAME for d in stack_layout.NPC_FOLDERS])


def build_new(base):
    """Новый файл из базы: только байты шанса, с проверкой, что это условие 7 навыка 18 нужного типа."""
    out = bytearray(base)
    for typ, off in RATE_OFFSETS.items():
        rec, entry = off // REC, off - 11
        if int.from_bytes(base[rec * REC:rec * REC + 2], "little", signed=True) != typ:
            raise RuntimeError("смещение %d: не запись типа %d" % (off, typ))
        if int.from_bytes(base[entry:entry + 2], "little") != 18 or base[entry + 2] != 7 or base[off] != OLD_RATE:
            raise RuntimeError("смещение %d: не условие 7 навыка 18 с шансом %d" % (off, OLD_RATE))
        out[off] = RATE
    return bytes(out)


def verify_pair(base, new):
    """Список расхождений пары: длина и ровно два изменённых байта."""
    bad = []
    if len(base) != len(new) or len(base) % REC:
        bad.append("длина %d/%d" % (len(base), len(new)))
    diff = [i for i in range(min(len(base), len(new))) if base[i] != new[i]]
    if sorted(diff) != sorted(RATE_OFFSETS.values()):
        bad.append("изменены байты %s" % diff[:10])
    return bad


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
    """Локальные файлы: md5 базы и нового, новый собирается из базы теми же байтами."""
    with open(LOCAL_BASE, "rb") as f:
        base = f.read()
    with open(LOCAL_NEW, "rb") as f:
        new = f.read()
    if md5(LOCAL_BASE) != BASE_MD5 or md5(LOCAL_NEW) != NEW_MD5 or build_new(base) != new:
        raise RuntimeError("локальные файлы не сошлись: запустите с --build")
    bad = verify_pair(base, new)
    if bad:
        raise RuntimeError("сверка пары: %s" % bad)
    log(lines, "  локальные файлы сошлись: %s → %s, изменено байт %d" % (BASE_MD5[:8], NEW_MD5[:8], len(RATE_OFFSETS)))


def backup(todo, lines):
    """Бэкап: рядом и в v2\\_backup со сверкой md5, локально из сверенной копии базы."""
    for rel in todo:
        src = V2 + "\\" + rel
        for dst in (src + SUFFIX, SRV_BACKUP + "\\" + rel):
            rc, out = ps("$d = Split-Path -Parent %s; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }; "
                         "if ((Md5Of %s) -eq 'none') { Copy-Item -LiteralPath %s -Destination %s }; Write-Output ('M|' + (Md5Of %s))" % (q(dst), q(dst), q(src), q(dst), q(dst)))
            got = [l[2:].strip() for l in out.splitlines() if l.startswith("M|")]
            if rc != 0 or not got or got[-1] != BASE_MD5:
                raise RuntimeError("бэкап %s: %s" % (dst, out[-300:]))
        loc = LOCAL_BACKUP + "/" + rel.replace("\\", "/")
        if os.path.exists(loc) and md5(loc) != BASE_MD5:
            raise RuntimeError("локальный бэкап %s уже есть и это другой файл" % loc)
        if not os.path.exists(loc):
            os.makedirs(os.path.dirname(loc), exist_ok=True)
            with open(LOCAL_BASE, "rb") as f, open(loc, "wb") as g:
                g.write(f.read())
        log(lines, "  бэкап: %s" % rel)


def upload(todo, lines):
    """Новый файл → stage по scp → сверка md5 → копия на место → сверка."""
    ps("New-Item -ItemType Directory -Force -Path %s | Out-Null; Write-Output OK" % q(STAGE))
    r = subprocess.run(["scp", "-q", "-i", r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@", "-o", "BatchMode=yes", LOCAL_NEW,
                        "Administrator@@@ASTORY_SERVER_VPN_IP@@:" + STAGE.replace("\\", "/") + "/"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("scp в stage: %s" % r.stderr.strip())
    staged = STAGE + "\\" + NAME
    st = md5_abs([staged])
    if st[staged] != NEW_MD5:
        raise RuntimeError("stage = %s, ожидался %s: ничего не скопировано" % (st[staged], NEW_MD5))
    for rel in todo:
        rc, out = ps("Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output ('M|' + (Md5Of %s))" % (q(staged), q(V2 + "\\" + rel), q(V2 + "\\" + rel)))
        got = [l[2:].strip() for l in out.splitlines() if l.startswith("M|")]
        ok = rc == 0 and got and got[-1] == NEW_MD5
        log(lines, "  %s выложено: %s %s" % (rel, got[-1] if got else "?", "OK" if ok else "НЕ СОШЛОСЬ"))
        if not ok:
            raise RuntimeError("после копии %s: %s" % (rel, out[-300:]))


def rollback(plan, cur, lines):
    """Откат: файлы, равные новому, из бэкапа рядом; код возврата."""
    todo = [rel for rel in plan if cur[rel] == NEW_MD5]
    for rel in plan:
        if cur[rel] not in (BASE_MD5, NEW_MD5):
            log(lines, "  ВНИМАНИЕ: %s = %s, не база и не новый: откат его не трогает" % (rel, cur[rel]))
    baks = md5_abs([V2 + "\\" + rel + SUFFIX for rel in todo]) if todo else {}
    for rel in todo:
        if baks[V2 + "\\" + rel + SUFFIX] != BASE_MD5:
            log(lines, "СТОП: %s%s нет или это не база: ничего не тронуто" % (rel, SUFFIX))
            return 6
    for rel in todo:
        rc, out = ps("Copy-Item -LiteralPath %s -Destination %s -Force; Write-Output ('M|' + (Md5Of %s))" % (q(V2 + "\\" + rel + SUFFIX), q(V2 + "\\" + rel), q(V2 + "\\" + rel)))
        got = [l[2:].strip() for l in out.splitlines() if l.startswith("M|")]
        ok = rc == 0 and got and got[-1] == BASE_MD5
        log(lines, "  %s откат: %s %s" % (rel, got[-1] if got else "?", "OK" if ok else "НЕ СОШЛОСЬ"))
        if not ok:
            return 5
    log(lines, "ГОТОВО: откачено файлов %d, стойку можно запускать" % len(todo))
    return 0


def build():
    """Собрать новый файл из базы и напечатать его md5."""
    if md5(LOCAL_BASE) != BASE_MD5:
        print("база не та: %s" % md5(LOCAL_BASE))
        return 1
    with open(LOCAL_BASE, "rb") as f:
        base = f.read()
    with open(LOCAL_NEW, "wb") as f:
        f.write(build_new(base))
    print("новый файл: %s" % md5(LOCAL_NEW))
    return 0


def main():
    """Точка входа: сухой прогон, --build, --apply, --rollback."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--build" in sys.argv:
        return build()
    apply = "--apply" in sys.argv
    undo = "--rollback" in sys.argv
    lines = []
    log(lines, "== deploy_loaderwalk_melee %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), "ОТКАТ" if undo else "ВЫКЛАДКА" if apply else "сухой прогон"))
    try:
        busy = busy_list()
        for rel in busy:
            log(lines, "  занят (процесс работает): " + rel)
        if busy and (apply or undo):
            log(lines, "СТОП: стойка не остановлена: ничего не тронуто")
            flush(lines)
            return 2
        plan = plan_files()
        cur = md5_rel(plan)
        if undo:
            rc = rollback(plan, cur, lines)
            flush(lines)
            return rc
        check_local(lines)
        todo = []
        for rel in plan:
            state = "база" if cur[rel] == BASE_MD5 else "уже новый" if cur[rel] == NEW_MD5 else "ЧУЖОЙ"
            log(lines, "  %s: %s (%s)" % (rel, cur[rel], state))
            if state == "ЧУЖОЙ":
                log(lines, "СТОП: md5 копии неожиданный: ничего не тронуто")
                flush(lines)
                return 3
            if state == "база":
                todo.append(rel)
        log(lines, "к выкладке: %d из %d" % (len(todo), len(plan)))
        if apply:
            backup(todo, lines)
            if todo:
                upload(todo, lines)
            log(lines, "ГОТОВО: выложено файлов %d" % len(todo))
        flush(lines)
        return 0
    except Exception as e:
        log(lines, "СТОП: %s" % e)
        flush(lines)
        return 1


if __name__ == "__main__":
    sys.exit(main())
