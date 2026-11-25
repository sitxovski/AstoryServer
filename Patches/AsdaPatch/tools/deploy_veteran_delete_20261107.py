# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_veteran_delete_20261107.py — удаление 5 вещей Veteran Reindeer 76156–76160 из dbo.Item, база Joy1 (слово владельца 07.11:
#   «5 veteran reindeer - remove from database»). Только при остановленной стойке: инвентарь онлайн-персонажа живёт в памяти GameServer.
#   SQL идёт локальными файлами AstoryServer/SQL через scp и sqlcmd -i. Сначала сохранение строк в Item_bak_veteran_20261107, затем удаление.
# Режимы: без ключа — проверка числа строк; --apply — сохранение и удаление; --rollback — возврат строк из таблицы сохранения.
# ★ ЗАКОН tools-no-import-side-effects: при импорте ничего не делает.
import os
import subprocess
import sys

SSH_KEY = r"C:\Users\@@ASTORY_DEV_USER@@\.ssh\@@ASTORY_SSH_KEY_NAME@@"        # ключ SSH
SSH_HOST = "Administrator@@@ASTORY_SERVER_VPN_IP@@"             # стойка
SQL_DIR = r"@@ASTORY_DEV_ROOT@@\AstoryServer\SQL"              # локальные файлы SQL
REMOTE = "C:/Windows/Temp/"                           # временная папка стойки для файлов SQL
BACKUP = "delete_veteran_reindeer_20261107_backup.sql"   # сохранение строк
DELETE = "delete_veteran_reindeer_20261107.sql"          # удаление строк
COUNT_Q = "SET NOCOUNT ON; SELECT CONCAT('N|', COUNT(*)) FROM dbo.Item WHERE Userindex = 75239 AND Charidx = 10 AND Code BETWEEN 76156 AND 76160;"   # остаток строк
RESTORE_Q = ("SET NOCOUNT ON; SET XACT_ABORT ON; BEGIN TRANSACTION; INSERT INTO dbo.Item SELECT * FROM dbo.Item_bak_veteran_20261107; "
             "IF @@ROWCOUNT <> 5 BEGIN ROLLBACK TRANSACTION; RAISERROR('Возвращено не 5 строк', 16, 1); END ELSE COMMIT TRANSACTION;")   # возврат строк


def ssh(cmd, timeout=180):
    """Команда на стойке по SSH → (код, вывод)."""
    p = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", SSH_HOST, cmd], capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def run_file(name):
    """Копирует файл SQL на стойку, выполняет его и удаляет → (код, вывод)."""
    p = subprocess.run(["scp", "-q", "-i", SSH_KEY, "-o", "BatchMode=yes", os.path.join(SQL_DIR, name), "%s:%s%s" % (SSH_HOST, REMOTE, name)], capture_output=True, timeout=120)
    if p.returncode != 0:
        return p.returncode, p.stderr.decode("utf-8", "replace")
    path = REMOTE + name
    rc, out = ssh('sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -W -i "%s"' % path)
    ssh('cmd /c del /q "%s"' % path.replace("/", "\\"))
    return rc, out


def query(text):
    """Короткий запрос к Joy1 → (код, вывод)."""
    return ssh('sqlcmd -S localhost\\SQLEXPRESS -E -d Joy1 -b -f 65001 -h -1 -W -Q "%s"' % text)


def left():
    """Число оставшихся строк 76156–76160 у персонажа; None, если не прочитано."""
    rc, out = query(COUNT_Q)
    line = [l.strip() for l in out.splitlines() if l.strip().startswith("N|")]
    return int(line[0].split("|")[1]) if rc == 0 and line else None


def main():
    """Выполняет режим; «ГОТОВО» печатается только после подтверждённого результата."""
    n = left()
    print("строк сейчас: %s" % n, flush=True)
    if n is None:
        print("ОТКАЗ: число строк не прочитано")
        return 13
    if "--rollback" in sys.argv:
        if n != 0:
            print("ОТКАЗ: строки уже есть, возврат не нужен")
            return 13
        rc, out = query(RESTORE_Q)
        print(out, flush=True)
        if rc == 0 and left() == 5:
            print("ГОТОВО: 5 строк возвращены")
            return 0
        return 13
    if "--apply" not in sys.argv:
        print("сухой прогон: %s" % ("всё готово к --apply" if n == 5 else "ОЖИДАЛОСЬ 5 строк"))
        return 0 if n == 5 else 13
    if n != 5:
        print("ОТКАЗ: ожидалось 5 строк")
        return 13
    for name in (BACKUP, DELETE):
        rc, out = run_file(name)
        print("== %s: код %d\n%s" % (name, rc, out), flush=True)
        if rc != 0:
            return 13
    if left() != 0:
        print("ОТКАЗ: строки остались")
        return 13
    print("ГОТОВО: 5 строк Veteran Reindeer удалены, сохранение в Item_bak_veteran_20261107")
    return 0


if __name__ == "__main__":
    sys.exit(main())
