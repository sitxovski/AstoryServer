# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# srv_mirror.py — локальное зеркало файлов dev-стойки для инструментов серверных патчей, снимаемое по SSH (22.10.2026).
#   Зачем: сетевая папка \\@@ASTORY_SERVER_HOSTNAME@@ висла целиком (листинг, чтение файлов работающих процессов — часами, без таймаута),
#   а verify_* / run_checks.py читали образы и таблицы с неё. Теперь они читают зеркало (корень — srv_paths.py).
#   ★ ТОЛЬКО ЧТЕНИЕ сервера: ни одной команды записи на стойку. Чтение — PowerShell на сервере (-EncodedCommand),
#     IO.FileStream(path, Open, Read, FileShare.ReadWrite) — не висит на файлах, открытых сервером; передача — base64 в stdout.
#   ★ У каждого шага предел времени (SSH ConnectTimeout 15 с, опрос метаданных 90 с, файл 300 с); md5 считается на сервере
#     по тем же байтам, что переданы, и сверяется после записи локально (размер + md5).
#   ★ Кэш: _srv_mirror/_manifest.json (размер, LastWriteTimeUtc, md5 на момент снятия). Неизменное (размер и время на
#     сервере = манифесту, локальная копия цела по md5) не перекачивается.
# Структура: tools/_srv_mirror/<путь относительно @@ASTORY_SERVER_ROOT@@\Working_ASDA> (например, v2/GameServer/GameServer.exe).
# Список FILES — всё, что читают инструменты (verify_* AsdaPatch/AsdaSecure/AddonNPC, run_checks.py, inject_import*.py,
#   сухой прогон data_levelcaps_20261022.py). Новый читаемый файл — добавить сюда.
# Запуск: python srv_mirror.py            — обновить зеркало (только изменившееся);
#         python srv_mirror.py --force    — перекачать всё;
#         python srv_mirror.py --check    — только сверить метаданные с сервером, ничего не качать;
#         python srv_mirror.py v2/X/y.txt — дополнительно снять указанные пути (в манифест попадут, в FILES — нет).
# Код возврата: 0 — зеркало полное и свежее; 1 — были ошибки (SSH/сверка), зеркало могло остаться прежним; 2 — не хватает файлов.
import base64
import hashlib
import json
import os
import subprocess
import sys
import time

KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"
HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST]
REMOTE_ROOT = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA"                                     # корень стойки (здесь — только чтение)
MIRROR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_srv_mirror")
MANIFEST = os.path.join(MIRROR, "_manifest.json")
T_STAT = 90                                                               # предел опроса метаданных, с
T_FILE = 300                                                              # предел снятия одного файла, с

FILES = [
    # образы — сверка площадок в verify_*, стенды NPC/DB в run_checks.py, источники inject_import*.py
    "AsdaStory/GameServer/GameServer.exe_before_mine_patch.exe",          # сток GameServer 4e20f0ad
    "AsdaStory/NpcServer/NpcServer.exe",                                  # сток NpcServer 16c7a0af
    "v2/GameServer/GameServer.exe",                                       # живой GameServer
    "v2/Indun_GameServer/GameServer.exe",                                 # живой Indun
    "v2/NpcServer/NpcServer.exe",                                         # живой NpcServer
    "v2/Indun_NpcServer/NpcServer.exe",                                   # живой Indun NpcServer
    "v2/DBManager/DBManager.exe",                                         # живой DBManager (P22/DBPatch)
    "v2/DBManager/DBManager-Original.exe",                                # сток DBManager
    "v2/LoginManager/LoginManager.exe",                                   # LoginManager стойки (verify_sites/verify_traffic)
    # таблицы — verify_p67 (сверка таблиц предметов/гачи)
    "v2/GameServer/ItemTable_Info/item_table.txt",
    "v2/GameServer/ItemTable_Info/PrimiumGaChaTable.txt",
    # таблицы — сухой прогон data_levelcaps_20261022.py
    "v2/GameServer/NpcData_Info/LimitationQuest.txt",
    "v2/GameServer/BattleField_Info/BattleField_BaseInfo.txt",
    "v2/Indun_GameServer/NpcData_Info/LimitationQuest.txt",
    "v2/Indun_GameServer/BattleField_Info/BattleField_BaseInfo.txt",
    # таблицы — verify_p87 (строки стартовых навыков 4-й профессии, категории/требования навыков) и стенд stand_p87
    "v2/GameServer/SkillTable_Info/ChangeJobAddSkillTable.txt",
    "v2/Indun_GameServer/SkillTable_Info/ChangeJobAddSkillTable.txt",
    "v2/GameServer/SkillTable_Info/SkillInfo.sif",
    "v2/Indun_GameServer/SkillTable_Info/SkillInfo.sif",
]
# ★ 26.10.2026 (канал 2): те же файлы копий Ch2_* (stack_layout.TWINS) — чтобы сухие прогоны видели все папки стойки.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_layout   # noqa: E402
FILES += [f.replace("v2/%s/" % field, "v2/%s/" % twin, 1) for f in list(FILES) for twin, field in stack_layout.TWINS.items()
          if f.startswith("v2/%s/" % field)]

PS_HEAD = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
"""


def ps(script, timeout):
    """PowerShell-скрипт на сервере через -EncodedCommand; возврат (код, stdout-строка, stderr-хвост). Таймаут → код -9."""
    enc = base64.b64encode((PS_HEAD + script).encode("utf-16-le")).decode("ascii")
    if len(enc) > 7000:
        # ★ 26.10.2026 (канал 2: список FILES вырос): командная строка Windows ≤ 8191 символа — длинный скрипт уходит
        #   ФАЙЛОМ (stack_parity.run_ps: scp во временный .ps1 + -File; только чтение, как и прежде).
        from stack_parity import run_ps
        try:
            rc, out, err = run_ps(PS_HEAD + script, timeout=timeout)
        except subprocess.TimeoutExpired:
            return -9, "", "таймаут %d с" % timeout
        return rc, out, err.strip()[-400:]
    try:
        p = subprocess.run(SSH + ["powershell -NoProfile -NonInteractive -EncodedCommand " + enc],
                           capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return -9, "", "таймаут %d с" % timeout
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace").strip()[-400:]


def q(s):
    """Строка PowerShell в одинарных кавычках."""
    return "'" + s.replace("'", "''") + "'"


def remote(rel):
    """Путь стойки для относительного пути зеркала."""
    return REMOTE_ROOT + "\\" + rel.replace("/", "\\")


def local(rel):
    """Путь в зеркале для относительного пути."""
    return os.path.join(MIRROR, *rel.split("/"))


def md5_file(p):
    """md5 локального файла (hex)."""
    h = hashlib.md5()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def stat_all(rels):
    """Метаданные файлов стойки одним вызовом: rel → (размер, LastWriteTimeUtc.Ticks) или None (файла нет)."""
    lines = ["$r = @(%s)" % ", ".join(q(r) for r in rels),
             "$p = @(%s)" % ", ".join(q(remote(r)) for r in rels),
             "for ($k = 0; $k -lt $r.Count; $k++) {",
             "  if (Test-Path -LiteralPath $p[$k] -PathType Leaf) { $i = Get-Item -LiteralPath $p[$k];",
             "    Write-Output ('{0}|{1}|{2}' -f $r[$k], $i.Length, $i.LastWriteTimeUtc.Ticks) }",
             "  else { Write-Output ('{0}|NONE' -f $r[$k]) } }",
             "Write-Output 'STAT-END'"]
    rc, out, err = ps("\n".join(lines), T_STAT)
    if rc != 0 or "STAT-END" not in out:
        raise RuntimeError("опрос метаданных по SSH: код %d %s %s" % (rc, err, out[-300:]))
    res = {}
    for ln in out.splitlines():
        f = ln.strip().split("|")
        if len(f) == 3 and f[0] in rels:
            res[f[0]] = (int(f[1]), int(f[2]))
        elif len(f) == 2 and f[1] == "NONE" and f[0] in rels:
            res[f[0]] = None
    miss = [r for r in rels if r not in res]
    if miss:
        raise RuntimeError("опрос метаданных: нет ответа по %s" % miss)
    return res


def fetch(rel):
    """Снять файл стойки: FileStream с FileShare.ReadWrite → md5 и base64 одних и тех же байт; сверка md5 здесь."""
    script = ("$fs = [IO.File]::Open(%s, 'Open', 'Read', 'ReadWrite')\n"
              "try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms) } finally { $fs.Close() }\n"
              "$b = $ms.ToArray()\n"
              "$h = [BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($b)) -replace '-', ''\n"
              "Write-Output ('MD5 ' + $h.ToLower() + ' ' + $b.Length)\n"
              "Write-Output ([Convert]::ToBase64String($b))\n" % q(remote(rel)))
    rc, out, err = ps(script, T_FILE)
    ls = [l.strip() for l in out.splitlines() if l.strip()]
    if rc != 0 or len(ls) < 2 or not ls[-2].startswith("MD5 "):
        raise RuntimeError("снятие %s по SSH: код %d %s %s" % (rel, rc, err, out[:200]))
    _, want, size = ls[-2].split()
    data = base64.b64decode(ls[-1])
    if len(data) != int(size) or hashlib.md5(data).hexdigest() != want:
        raise RuntimeError("снятие %s: принято %d б md5 %s, на сервере %s б md5 %s" % (
            rel, len(data), hashlib.md5(data).hexdigest(), size, want))
    return data, want


def load_manifest():
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_manifest(m):
    os.makedirs(MIRROR, exist_ok=True)
    tmp = MANIFEST + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(m, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, MANIFEST)


def present(rels=None):
    """Есть ли в зеркале все файлы (по манифесту и размеру) — без сети."""
    m = load_manifest()
    return [r for r in (rels or FILES)
            if r not in m or not os.path.isfile(local(r)) or os.path.getsize(local(r)) != m[r]["size"]]


def update(rels=None, force=False, check=False, log=print):
    """Обновить зеркало. Возврат: 0 — полное и свежее, 1 — ошибки (часть могла остаться прежней), 2 — не хватает файлов."""
    rels = list(rels or FILES)
    t0 = time.time()
    m = load_manifest()
    errors = 0
    try:
        st = stat_all(rels)
    except Exception as e:  # noqa: BLE001 — SSH недоступен: зеркало остаётся прежним
        log("[srv_mirror] [!!] сервер недоступен по SSH: %s — зеркало НЕ обновлено" % e)
        miss = present(rels)
        if miss:
            log("[srv_mirror] [!!] в зеркале нет: %s" % ", ".join(miss))
            return 2
        return 1
    got = same = 0
    for rel in rels:
        lp = local(rel)
        meta = st[rel]
        if meta is None:
            log("[srv_mirror] [!!] на сервере НЕТ %s" % remote(rel))
            errors += 1
            continue
        size, ticks = meta
        e = m.get(rel)
        fresh = (e is not None and e.get("size") == size and e.get("ticks") == ticks and os.path.isfile(lp)
                 and os.path.getsize(lp) == size and md5_file(lp) == e.get("md5"))
        if fresh and not force:
            same += 1
            continue
        if check:
            log("[srv_mirror] устарело: %s (сервер %d б, время %d)" % (rel, size, ticks))
            errors += 1
            continue
        try:
            data, h = fetch(rel)
        except Exception as ex:  # noqa: BLE001
            log("[srv_mirror] [!!] %s" % ex)
            errors += 1
            continue
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        tmp = lp + ".part"
        with open(tmp, "wb") as f:
            f.write(data)
        if os.path.getsize(tmp) != len(data) or md5_file(tmp) != h:
            log("[srv_mirror] [!!] запись %s не сошлась" % lp)
            errors += 1
            continue
        os.replace(tmp, lp)
        m[rel] = {"size": len(data), "ticks": ticks, "md5": h, "fetched": time.strftime("%Y-%m-%d %H:%M:%S")}
        save_manifest(m)
        got += 1
        log("[srv_mirror] снят %s %d б md5 %s" % (rel, len(data), h))
    miss = present(rels)
    log("[srv_mirror] итог: снято %d, без изменений %d, ошибок %d, нет в зеркале %d; %.0f с; зеркало %s" % (
        got, same, errors, len(miss), time.time() - t0, MIRROR))
    if miss:
        return 2
    return 1 if errors else 0


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = sys.argv[1:]
    force = "--force" in args
    check = "--check" in args
    extra = [a.replace("\\", "/").strip("/") for a in args if not a.startswith("--")]
    for a in extra:
        if ".." in a.split("/"):
            sys.exit("путь %r вне Working_ASDA" % a)
    rels = FILES + [a for a in extra if a not in FILES]
    sys.exit(update(rels, force=force, check=check))


if __name__ == "__main__":
    main()
