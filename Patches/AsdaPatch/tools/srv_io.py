# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# srv_io.py — чтение и запись файлов dev-стойки ТОЛЬКО по SSH (26.10.2026, channel2; правило владельца 22.10: шару \\@@ASTORY_SERVER_HOSTNAME@@
#   не трогать — висит без таймаута). Общая точка для скриптов данных, которые раньше читали/писали \\@@ASTORY_SERVER_HOSTNAME@@ напрямую
#   (build_fishbooks, build_hunt_signs/make_diff, apply_npc_boards, server_item_tail_extend).
#   • read_live(rel)  — байты файла v2\<rel> через кэш srv_mirror (по SSH, FileShare.ReadWrite, сверка md5; свежесть —
#                       по размеру и времени файла на сервере). Только чтение сервера.
#   • live_md5(rel)   — md5 файла на сервере ('none' — нет).
#   • put_live(rel, data, suffix, srv_backup, local_backup) — запись: файл не занят процессом → бэкап рядом (<файл><suffix>),
#                       в v2\_backup\…\<rel> и локально (существующие бэкапы не перезаписываются, md5 сверяется) →
#                       scp во временный <файл>.srvio_upload (md5) → копия поверх → сверка md5.
#   rel — путь от v2 с '/' или '\' (например 'GameServer/ItemTable_Info/item_table.txt').
# Без побочных эффектов при импорте. Удалений нет, кроме собственного временного файла заливки (rdel).
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import srv_mirror   # noqa: E402  кэш по SSH (только чтение)
from deploy_p90 import ps, q, rmd5, rbusy, rcopy, rupload, rdel, rread   # noqa: E402  общие функции SSH

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"


class SrvIoError(RuntimeError):
    """Ошибка чтения/записи стойки по SSH (ничего не записано или запись прервана со сверкой)."""


def _rel(rel):
    return rel.replace("\\", "/").strip("/")


def remote_path(rel):
    """Полный путь файла на стойке."""
    return V2 + "\\" + _rel(rel).replace("/", "\\")


def read_live(rel, quiet=True):
    """Байты живого файла v2/<rel> (через зеркало srv_mirror; свежесть сверяется с сервером при каждом вызове)."""
    mrel = "v2/" + _rel(rel)
    logs = []
    rc = srv_mirror.update([mrel], log=logs.append if quiet else print)
    lp = srv_mirror.local(mrel)
    if rc != 0 or not os.path.isfile(lp):
        raise SrvIoError("чтение %s по SSH не удалось (код %d): %s" % (mrel, rc, " | ".join(logs[-3:])))
    with open(lp, "rb") as f:
        return f.read()


def live_md5(rel):
    """md5 файла на стойке ('none' — нет)."""
    return rmd5(remote_path(rel))


def _rdel_upload(path):
    """Удалить ТОЛЬКО собственный временный файл заливки (*.srvio_upload) — иные пути отвергаются."""
    if not path.endswith(".srvio_upload"):
        raise SrvIoError("отказ удалять %s: srv_io удаляет только свои *.srvio_upload" % path)
    rdel(path)


def put_live(rel, data, suffix, srv_backup, local_backup, log=print):
    """Записать data в v2/<rel> по SSH с бэкапами (см. шапку). Возврат md5 записанного."""
    dst = remote_path(rel)
    want = hashlib.md5(data).hexdigest()
    st = rbusy(dst)
    if st == "BUSY":
        raise SrvIoError("%s занят процессом стойки — запись отменена" % dst)
    cur = rmd5(dst)
    if cur == want:
        log("  %s: уже нужный (%s) — пропуск" % (_rel(rel), want))
        return want
    if cur != "none":
        # бэкапы: рядом и в v2\_backup (не перезаписывать существующие), локально
        for b in (dst + suffix, srv_backup.rstrip("\\") + "\\" + _rel(rel).replace("/", "\\")):
            have = rmd5(b)
            if have == "none":
                rcopy(dst, b)
                have = rmd5(b)
                if have != cur:
                    raise SrvIoError("бэкап %s не сошёлся (%s ≠ %s) — запись отменена" % (b, have, cur))
                log("  бэкап: %s %s" % (b, cur))
            elif have != cur:
                log("  бэкап %s уже есть (%s) — прежний сохранён, новый не пишется" % (b, have))
        loc = os.path.join(local_backup, *_rel(rel).split("/"))
        if not os.path.exists(loc):
            raw = rread(dst)
            if hashlib.md5(raw).hexdigest() != cur:
                raise SrvIoError("прочитанное по SSH %s не сошлось по md5 — запись отменена" % dst)
            os.makedirs(os.path.dirname(loc), exist_ok=True)
            with open(loc, "wb") as f:
                f.write(raw)
            log("  локальный бэкап: %s %d б" % (loc, len(raw)))
    tmp_local = os.path.join(os.environ.get("TEMP", HERE), "srvio_%d_%s" % (os.getpid(), os.path.basename(dst)))
    with open(tmp_local, "wb") as f:
        f.write(data)
    up = dst + ".srvio_upload"
    rc, out = ps("New-Item -ItemType Directory -Force -Path (Split-Path -Parent %s) | Out-Null; Write-Output OK" % q(up))
    if rc != 0 or not out.endswith("OK"):
        raise SrvIoError("папка для %s не создана: %s" % (dst, out[-200:]))
    try:
        rupload(tmp_local, up)
        if rmd5(up) != want:
            _rdel_upload(up)
            raise SrvIoError("залитый %s не сошёлся по md5 — %s не тронут" % (up, dst))
        rcopy(up, dst)
        _rdel_upload(up)
    finally:
        try:
            os.remove(tmp_local)
        except OSError:
            pass
    got = rmd5(dst)
    if got != want:
        raise SrvIoError("после записи %s = %s, ожидался %s" % (dst, got, want))
    log("  записано %s %d б md5 %s" % (_rel(rel), len(data), got))
    return got
