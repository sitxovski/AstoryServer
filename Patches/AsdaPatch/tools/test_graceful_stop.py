# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# test_graceful_stop.py — проверка шага 3а restart_stack.py «штатное завершение GameServer» (07.11.2026, баг 9) без стойки.
#   SSH подменён: сценарии — норма, зависший GS, БД не успела, сбой SSH. Сверяются: содержимое залитого сценария (base64 = GRACEFUL_SCRIPT,
#   SC_CLOSE 0x112/0xF060, класс #32770), порядок команд (задача /IT → опрос → удаление задачи и файлов → опрос БД), пределы ожидания,
#   шаг стоит ДО Stop-Process и завёрнут в try, выключатель --no-graceful-stop. Запуск: py -3.13 test_graceful_stop.py
import base64
import os
import re
import sys

sys.dont_write_bytecode = True
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import restart_stack as rs

OK = 0
BAD = 0


def check(cond, what):
    """Строка «[OK]/[FAIL] что» и счётчики."""
    global OK, BAD
    if cond:
        OK += 1
        print("[OK]   " + what)
    else:
        BAD += 1
        print("[FAIL] " + what)


class Clock:
    """Подмена time: sleep двигает часы, настоящего ожидания нет."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s

    def strftime(self, f):
        return "00:00:00"


def run(gs, db, fail=False):
    """graceful_stop с подменённым ssh_ps: gs/db — последовательности ответов (последний повторяется). → (итог, журнал команд)."""
    log = []
    gs, db = list(gs), list(db)

    def fake(cmd, timeout=180):
        log.append(cmd)
        if fail:
            raise RuntimeError("ssh упал")
        if "Get-Process GameServer" in cmd:
            return 0, "%d\r\n" % (gs.pop(0) if len(gs) > 1 else gs[0])
        if "sqlcmd" in cmd:
            return 0, "%d\r\n" % (db.pop(0) if len(db) > 1 else db[0])
        if "Get-Content" in cmd:
            return 0, "processes=3 windows=3\r\n"
        return 0, ""

    rs.ssh_ps = fake
    rs.time = Clock()
    return rs.graceful_stop(), log


def main():
    r, log = run([3, 3, 0], [2, 0])
    check(r == (True, 0), "норма: GS вышли, в игре 0 — %s" % (r,))
    m = re.search(r"FromBase64String\('([^']+)'\)", log[0])
    body = base64.b64decode(m.group(1)).decode("ascii") if m else ""
    check(body == rs.GRACEFUL_SCRIPT, "на сервер заливается ровно GRACEFUL_SCRIPT")
    check("0x112" in body and "0xF060" in body and '"#32770"' in body and "Get-Process -Name GameServer" in body,
          "сценарий: WM_SYSCOMMAND SC_CLOSE окнам #32770 процессов GameServer")
    check("/RU Administrator /IT" in log[0] and "schtasks /Run" in log[0], "первая команда — задача /IT и её запуск")
    i_del = next(i for i, c in enumerate(log) if "schtasks /Delete" in c)
    i_sql = next(i for i, c in enumerate(log) if "sqlcmd" in c)
    check(0 < i_del < i_sql and "Remove-Item" in log[i_del], "задача и файлы удаляются до опроса БД")
    check("Usernum <> -1" in log[i_sql], "опрос БД — остаток «в игре» по CharPos")

    r, log = run([3], [0])
    polls = sum("Get-Process GameServer" in c for c in log)
    check(r == (False, None) and polls == rs.GRACEFUL_GS_SEC // 3, "зависший GS: предел %d с (%d опросов), БД не опрашивается — %s" % (rs.GRACEFUL_GS_SEC, polls, r))
    check(any("schtasks /Delete" in c for c in log), "зависший GS: задача всё равно удалена")

    r, log = run([0], [5])
    check(r == (True, 5) and sum("sqlcmd" in c for c in log) == rs.GRACEFUL_DB_SEC // 3, "БД не успела: предел %d с — %s" % (rs.GRACEFUL_DB_SEC, r))

    try:
        run([0], [0], fail=True)
        raised = False
    except RuntimeError:
        raised = True
    check(raised, "сбой SSH поднимается наверх (его ловит try в main)")

    s = open(os.path.join(HERE, "restart_stack.py"), encoding="utf-8").read()
    # ★ 19.11.2026 (А3, ревизия 32 Н-М1): шаг 3 вынесен в stop_all() — в main после graceful_stop() идёт вызов stop_all()
    a, c = s.find('say("3а. штатное завершение GameServer (SC_CLOSE'), s.find("            graceful_stop()\n")
    b = s.find("stopped = stop_all()", c)
    check('say("3. остановка стойки")' in s[s.find("def stop_all"):s.find("def main")], "stop_all: шаг 3 «остановка стойки»")
    t = s.rfind("try:", 0, c)
    check(0 < a < c < b and a < t < c, "main: шаг 3а до Stop-Process, вызов внутри try")
    check('"--no-graceful-stop" in sys.argv' in s, "выключатель --no-graceful-stop")
    check(rs.GRACEFUL_SCRIPT.isascii(), "сценарий только ASCII (Set-Content/WriteAllBytes без кодировки)")
    print("test_graceful_stop ИТОГ: OK %d, FAIL %d" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
