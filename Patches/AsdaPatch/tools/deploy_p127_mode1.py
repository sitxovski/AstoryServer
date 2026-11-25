# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_p127_mode1.py — P127_AdminBridge: включение исполнения команд (Mode=0 «только слушать» -> Mode=1) — 18.11.2026, слово владельца
#   «Включай сразу». DLL не меняется (v80 d1581b14…); меняется только ключ Mode секции [P127_AdminBridge] в ConfigSet\patches.ini всех
#   GameServer из stack_layout. DLL читает ключ при старте, поэтому — через restart_stack с объявлением:
#     py -3.13 restart_stack.py --deploy deploy_p127_mode1.py --expect P127_AdminBridge --expect P21_TitleMask512 --expect P123_GmMapJump
#   После старта: py -3.13 deploy_p127_mode1.py --check-started (узлы моста: пульс, Mode=1).
#   Откат: ASDA_P127M1_ROLLBACK=1 + --apply (или --rollback) — Mode=0 (тем же рестартом).
#   Бэкап ini: рядом (.bak_20261118_p127m1), в v2\_backup\2026-11-18_p127m1 и локально. Без --apply — сухой прогон.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import hashlib
import os
import re
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _env():
    sys.path.insert(0, HERE)
    import deploy_p127 as d       # noqa: E402  ini_state, check_started, константы выкладки P127
    import stack_layout           # noqa: E402
    from deploy_p90 import rmd5, rread, rcopy, rupload, rdel, rbusy   # noqa: E402
    return d, stack_layout, rmd5, rread, rcopy, rupload, rdel, rbusy


SUFFIX = ".bak_20261118_p127m1"
LOCAL_BACKUP = "@@ASTORY_DEV_ROOT_FWD@@/_backup/2026-11-18_p127m1/server/v2"


def set_mode(text, want):
    """Ключ Mode в секции [P127_AdminBridge] -> want (строки секции, остальное дословно). → (новый текст, прежнее значение)."""
    out, cur, old, done = [], None, None, False
    for ln in text.splitlines(keepends=True):
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip()
        elif cur == "P127_AdminBridge" and re.match(r"(?i)^mode\s*=", s):
            old = s.split("=", 1)[1].strip()
            eol = ln[len(ln.rstrip("\r\n")):]
            ln = "Mode=%s%s" % (want, eol)
            done = True
        out.append(ln)
    if not done:
        raise RuntimeError("в секции [P127_AdminBridge] нет ключа Mode")
    return "".join(out), old


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    d, sl, rmd5, rread, rcopy, rupload, rdel, rbusy = _env()
    apply = "--apply" in sys.argv
    rollback = "--rollback" in sys.argv or (apply and os.environ.get("ASDA_P127M1_ROLLBACK") == "1")
    want = "0" if rollback else "1"
    lines = []
    d.log(lines, "== deploy_p127_mode1 %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
          "ПРОВЕРКА СТАРТА" if "--check-started" in sys.argv else ("ОТКАТ (Mode=0)" if rollback else "Mode=1") + (" ЗАПИСЬ" if apply else " сухой прогон")))
    if "--check-started" in sys.argv:
        rc = d.check_started(lines)
        d.flush(lines)
        return rc
    try:
        busy = [g for g in sl.GS_FOLDERS if rbusy(d.V2 + "\\" + g + r"\GameServer.exe") == "BUSY"]
        if busy and apply:
            d.log(lines, "СТОП: стойка не остановлена (%s) — ничего не тронуто" % ", ".join(busy))
            d.flush(lines)
            return 2
        plan = []
        for g in sl.GS_FOLDERS:
            path = d.V2 + "\\" + g + "\\" + d.INI_REL
            dll = rmd5(d.V2 + "\\" + g + r"\AsdaPatch.dll")
            if dll != d.WANT_DLL:
                d.log(lines, "СТОП: %s\\AsdaPatch.dll = %s, ожидалась v80 %s" % (g, dll, d.WANT_DLL))
                d.flush(lines)
                return 8
            raw = rread(path)
            if raw[:2] != b"\xff\xfe":
                d.log(lines, "СТОП: %s — patches.ini не UTF-16LE" % path)
                d.flush(lines)
                return 8
            new, old = set_mode(raw.decode("utf-16"), want)
            d.log(lines, "%s: [P127_AdminBridge] Mode %s -> %s" % (g, old, want))
            if old != want:
                plan.append((g, path, raw, new.encode("utf-16")))
        if not apply:
            d.log(lines, "сухой прогон: менять %d папок (%s)" % (len(plan), ", ".join(p[0] for p in plan) or "—"))
            d.flush(lines)
            return 0
        for g, path, raw, data in plan:
            src_md5 = hashlib.md5(raw).hexdigest()
            for dst in (path + SUFFIX, d.V2 + r"\_backup\2026-11-18_p127m1" + "\\" + g + "\\" + d.INI_REL):
                if rmd5(dst) == "none":
                    rcopy(path, dst)
                if rmd5(dst) != src_md5:
                    raise RuntimeError("бэкап %s не сошёлся" % dst)
            loc = LOCAL_BACKUP + "/" + g + "/" + d.INI_REL.replace("\\", "/")
            os.makedirs(os.path.dirname(loc), exist_ok=True)
            if not os.path.exists(loc):
                with open(loc, "wb") as f:
                    f.write(raw)
            tmp = os.path.join(tempfile.mkdtemp(prefix="p127m1_"), "patches.ini")
            with open(tmp, "wb") as f:
                f.write(data)
            want_md5 = hashlib.md5(data).hexdigest()
            up = path + ".p127m1_upload"
            rupload(tmp, up)
            if rmd5(up) != want_md5:
                rdel(up)
                raise RuntimeError("залитый %s не сошёлся" % up)
            rcopy(up, path)
            rdel(up)
            if rmd5(path) != want_md5:
                raise RuntimeError("после записи %s md5 не сошёлся" % path)
            _m, _v, has, keys = d.ini_state(g)
            if keys.get("Mode") != want:
                raise RuntimeError("после записи %s читается Mode=%s" % (path, keys.get("Mode")))
            d.log(lines, "  %s: patches.ini %s (Mode=%s), бэкап %s" % (g, want_md5, want, SUFFIX))
        d.log(lines, "ГОТОВО: [P127_AdminBridge] Mode=%s в %d папках. Дальше restart_stack: start.bat; затем "
                     "py -3.13 deploy_p127_mode1.py --check-started." % (want, len(plan)))
    except Exception as e:
        d.log(lines, "ОШИБКА: %s" % e)
        d.flush(lines)
        return 7
    d.flush(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
