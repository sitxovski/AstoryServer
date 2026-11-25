# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# deploy_ella_p40.py — ВЫКЛАДКА / ОТКАТ строки Crystals секции [P40_CrystalTeleportGate] (06.11.2026, просьба владельца:
#   «открыть вход в Забытую Лощину через Эллу»). Причина: кнопка порта 30037 у Эллы (NPC 107) появилась 27.09 в один день с P40,
#   в таблицу не попала; каждое нажатие — «P40: 5477 refused … map 3 -> 5», игрок видел нотис 1096. Других входов на карту 5 нет.
#   Меняется ТОЛЬКО значение Crystals в ConfigSet\patches.ini всех GameServer из stack_layout.GS_FOLDERS (+ ;107:5). DLL НЕ меняется:
#   значение читается из ini при старте, новая DLL не нужна (умолчание в Config.cpp поправлено для следующих сборок).
#   Запуск: py -3.13 restart_stack.py --deploy deploy_ella_p40.py --expect P40_CrystalTeleportGate
# Режимы: (без ключа) — сухой прогон (только чтение по SSH); --apply — стойка ОСТАНОВЛЕНА; --rollback — ini из <файл>.bak_20261106_ella.
#   ASDA_ELLA_ROLLBACK=1 + --apply — то же, что --rollback (так зовёт restart_stack).
# Коды возврата: 0 готово; 2 стойка не остановлена; 4 md5 не сошёлся после записи; 6 нет бэкапа; 7 исключение; 8 строка на стойке не та.
# Журнал: tools/run_ella_p40_20261106/deploy.log (дописывается).
import hashlib
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_layout   # единый состав стойки (канал 2: Ch2_*)
from deploy_p90 import rmd5, rbusy, rread, rcopy, rupload   # общие функции SSH (без побочных эффектов)

V2 = r"@@ASTORY_SERVER_ROOT@@\Working_ASDA\v2"
INI_REL = r"ConfigSet\patches.ini"
OLD = "Crystals=46:7,0,1;49:3;50:7,3,6,2;51:6,0;52:2,0;53:3,0,16;55:3;201:7"
NEW = OLD + ";107:5"
SUFFIX = ".bak_20261106_ella"
RUN_DIR = os.path.join(HERE, "run_ella_p40_20261106")
LOG = os.path.join(RUN_DIR, "deploy.log")


def say(lines, line):
    """Строка в консоль и в накопитель журнала."""
    print(line, flush=True)
    lines.append(line)


def flush(lines):
    """Дописать накопленные строки в журнал выкладки."""
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def patched(folder):
    """Прочитать живой ini папки → (байты, новые байты или None, если строка уже новая). Чужая строка — ValueError."""
    data = rread(V2 + "\\" + folder + "\\" + INI_REL)
    if data[:2] != b"\xff\xfe":
        raise ValueError("%s: ini не UTF-16 LE с BOM" % folder)
    old_b, new_b = OLD.encode("utf-16-le"), NEW.encode("utf-16-le")
    eol = "\r\n".encode("utf-16-le")
    if data.count(new_b + eol) == 1:
        return data, None
    if data.count(old_b + eol) != 1:
        raise ValueError("%s: строка Crystals не та (ожидалась прежняя или новая)" % folder)
    return data, data.replace(old_b + eol, new_b + eol)


def apply_all(lines):
    """Записать новую строку во все папки; бэкап рядом с файлом. Возврат — код."""
    for d in stack_layout.GS_FOLDERS:
        path = V2 + "\\" + d + "\\" + INI_REL
        data, new = patched(d)
        if new is None:
            say(lines, "%s: уже новая строка — пропуск" % d)
            continue
        rcopy(path, path + SUFFIX)
        if rmd5(path + SUFFIX).lower() != hashlib.md5(data).hexdigest():
            say(lines, "!! %s: бэкап не сошёлся — стоп" % d)
            return 4
        fd, tmp = tempfile.mkstemp(suffix=".ini")
        with os.fdopen(fd, "wb") as f:
            f.write(new)
        rupload(tmp, path)
        os.unlink(tmp)
        got = rmd5(path).lower()
        if got != hashlib.md5(new).hexdigest():
            say(lines, "!! %s: md5 после записи не сошёлся (%s)" % (d, got))
            return 4
        say(lines, "%s: Crystals + ;107:5, размер %d → %d, md5 %s, бэкап %s" % (d, len(data), len(new), got, SUFFIX))
    return 0


def rollback(lines):
    """Вернуть ini из бэкапа во всех папках. Возврат — код."""
    for d in stack_layout.GS_FOLDERS:
        path = V2 + "\\" + d + "\\" + INI_REL
        if rmd5(path + SUFFIX) == "none":
            say(lines, "!! %s: нет бэкапа %s" % (d, SUFFIX))
            return 6
        fd, tmp = tempfile.mkstemp(suffix=".ini")
        with os.fdopen(fd, "wb") as f:
            f.write(rread(path + SUFFIX))
        rupload(tmp, path)
        os.unlink(tmp)
        say(lines, "%s: ini возвращён из бэкапа" % d)
    return 0


def main():
    """Точка входа: сухой прогон, --apply или --rollback."""
    lines = []
    want_rb = "--rollback" in sys.argv or os.environ.get("ASDA_ELLA_ROLLBACK") == "1"
    want_apply = "--apply" in sys.argv
    rc = 0
    try:
        if not (want_apply or want_rb):
            for d in stack_layout.GS_FOLDERS:
                data, new = patched(d)
                say(lines, "%s: ini %d б, %s" % (d, len(data), "уже новая строка" if new is None else "к замене ровно 1 строка Crystals"))
            say(lines, "СУХОЙ ПРОГОН: записи не было")
            return 0
        for d in stack_layout.GS_FOLDERS:
            if rbusy(V2 + "\\" + d + r"\GameServer.exe") == "BUSY":
                say(lines, "!! %s: GameServer.exe занят — стойка не остановлена" % d)
                return 2
        rc = rollback(lines) if want_rb else apply_all(lines)
        if rc == 0:
            say(lines, "ГОТОВО: %s Crystals (папок %d)" % ("ОТКАТ" if want_rb else "выложено", len(stack_layout.GS_FOLDERS)))
        return rc
    except ValueError as e:
        say(lines, "!! %s" % e)
        return 8
    except Exception as e:   # сеть/SSH — стойку не трогаем дальше
        say(lines, "!! исключение: %r" % (e,))
        return 7
    finally:
        flush(lines)


if __name__ == "__main__":
    sys.exit(main())
