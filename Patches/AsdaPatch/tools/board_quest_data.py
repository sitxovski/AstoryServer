# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# board_quest_data.py — ДАННЫЕ волны board_quest (решения владельца 28.10.2026, спецификация
#   Docs/Port/systems/BOARD_QUEST_FLOW.md §4.3–4.4, §6, §12): серверная таблица «ограниченных заданий» доски объявлений
#   (LimitationQuest, 20000…20056) переписывается ПОД КЛИЕНТ, плюс строки Monster.ai для нового задания 20056.
#
# Источник чисел (решение владельца 1): клиентская таблица Interlude `Donors/AsdaChroniclesInterlude/Data/NPC/Raid_quest_data.BIN`
#   (RQD, запись 388 б; числа совпадают с _MINE побайтно — сверено 28.10, различаются только имена). Порт импортирует её же.
#   Правила переноса в серверный формат (загрузчики GS sub_4BD710@0x4BD710 и NpcServer sub_41F580, запись 216 б):
#     * столбцы: id тип max имя зона lvMin lvMax режим предм×5 кол×5 выбор×4 кол×4 опыт золото предм×2 кол×2 (32 поля, TAB, CRLF);
#     * «имя» (столбец 4) — номер задания, как во всех серверных копиях (сервер имя не показывает);
#     * lvMax 99 клиента → 100 (решение владельца 22.10.2026 «потолки уровня»: 99 у оригинала = «без верхнего предела», а наш
#       MaxLevel = 100 по P29; data_levelcaps_20261022.py). Прочие lvMax (45, 50, 59, 60 …) — как в клиенте;
#     * 20026 — режим 0 (у клиента 0; на сервере стоял 4 → GS RecvUser_LimitationQuestResult уходил в «иное» и не сдавал никогда —
#       решение владельца 4);
#     * 20055 / 20056 — новые строки (сервер их не знал → код 2 «Сведения о задании неверны»).
# Monster.ai (NpcServer\Monster и GameServer\MonsterData_Info): засчёт убийства для заданий режима 0 NpcServer берёт ТОЛЬКО из
#   списка квестовых условий моба (запись 479 б, флаг +402, до 6 условий по 12 б с +403: i32 questId, u8 шаг, u16 0, i32 предмет,
#   i8 шанс %; разбор sub_437320@0x437320 и вызывающих, NpcServer.exe.c:40709/40841/41806). Для 20056 «Охота на попугаев»
#   (предмет 79427 «Dia_Parrot» ×50, зона 16 Fireway Forest) условий не было ни у кого → задание не засчитывалось. Добавляется
#   условие (20056, 79427, 40 %) мобам 817 «다이아패럿» и 818 «순찰자_다이아패럿» (Dia Parrot / патрульный; оба спаунятся в
#   FirewayForest.svr: 8 и 4 точки). Шанс 40 — как у ВСЕХ заданий Fireway Forest в Monster.ai (20047, 20049–20054).
#   Условие пишется в ПЕРВЫЙ слот (у 817/818 все 6 пустые: ff ff ff ff ff ffff ffffffff 00); прочие байты не трогаются.
#
# Подкоманды (на сервер НИЧЕГО не пишет; выкладка — deploy_board_quest.py):
#   python board_quest_data.py build [--items <item_table.txt>] — собрать data_board_quest/LimitationQuest.txt и
#       Monster_<база>.ai из data_p91b (базы c4da0022 — поле/Ch2/NpcServer, 08c20c96 — Indun_GameServer), проверить, вывести
#       сводку «было → стало» (было — снимок живой таблицы tools/data_board_quest/base/LimitationQuest_GS_da2846ef.txt).
#   python board_quest_data.py table — таблица изменений (markdown) для отчёта.
#   python board_quest_data.py coverage — чем засчитываются цели каждого задания (условия Monster.ai / выпадение).
# Модуль без побочных эффектов при импорте (памятка tools-no-import-side-effects).
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data_board_quest")                                              # папка данных волны
CLIENT_BIN = r"@@ASTORY_DEV_ROOT@@\Donors\AsdaChroniclesInterlude\Data\NPC\Raid_quest_data.BIN"   # эталон чисел (Interlude)
CLIENT_NPC = r"@@ASTORY_DEV_ROOT@@\Donors\AsdaChroniclesInterlude\Data\NPC\Raid_npc_data.BIN"     # доски NPC 9/10 (RQN)
CLIENT_MD5 = "1aae82df4140dfee78682f14d4037f28"                                            # md5 эталонной Raid_quest_data.BIN
BASE_GS = os.path.join(OUT, "base", "LimitationQuest_GS_da2846ef.txt")                    # снимок живой GS-таблицы (до правки)
P91B = os.path.join(HERE, "data_p91b")                                                     # локальные копии живых Monster.ai
REC_AI = 479                                                                               # запись Monster.ai
AI_COND = 403                                                                              # первое условие квеста в записи
AI_FLAG = 402                                                                              # флаг «есть условия»
EMPTY_COND = bytes.fromhex("ffffffffffffffffffffff00")                                     # пустой слот условия (12 б)
NEW_COND = {817: (20056, 79427, 40), 818: (20056, 79427, 40)}                              # моб → (задание, предмет, шанс %)
AI_BASES = {   # md5 живой Monster.ai → (локальный файл-основа, где стоит)
    "c4da0022f45ac5dec75e0309246fb0e6": (os.path.join(P91B, "NpcServer", "Monster", "Monster.ai"),
                                         "GameServer/Ch2_GameServer MonsterData_Info, NpcServer/Indun_NpcServer/Ch2_NpcServer Monster"),
    "08c20c9605369dc97fb7145730cde863": (os.path.join(P91B, "Indun_GameServer", "MonsterData_Info", "Monster.ai"),
                                         "Indun_GameServer MonsterData_Info"),
}
FIELDS = ["id", "type", "max", "name", "zone", "lvmin", "lvmax", "mode"] + ["req%d" % i for i in range(5)] + \
         ["reqc%d" % i for i in range(5)] + ["ch%d" % i for i in range(4)] + ["chc%d" % i for i in range(4)] + \
         ["exp", "gold", "it0", "it1", "itc0", "itc1"]                                   # 32 столбца серверной строки


def md5b(b):
    """md5 байтов (hex)."""
    return hashlib.md5(b).hexdigest()


def read_client(path=CLIENT_BIN):
    """Raid_quest_data.BIN → список словарей FIELDS (числа клиента, без серверных правил)."""
    b = open(path, "rb").read()
    if b[12:15] != b"RQD":
        raise SystemExit("%s: нет магии RQD" % path)
    n = struct.unpack_from("<i", b, 4)[0]
    if len(b) != 0x14 + 388 * n:
        raise SystemExit("%s: размер %d ≠ 0x14 + 388·%d" % (path, len(b), n))
    out = []
    for k in range(n):
        o = 0x14 + 388 * k
        g = lambda off: struct.unpack_from("<i", b, o + off)[0]   # i32 записи
        r = {"id": g(0), "type": g(4), "max": g(8), "zone": g(76), "lvmin": g(80), "lvmax": g(84), "mode": g(88),
             "exp": g(364), "gold": g(368)}
        for i in range(5):
            r["req%d" % i], r["reqc%d" % i] = g(92 + 4 * i), g(112 + 4 * i)
        for i in range(4):
            r["ch%d" % i], r["chc%d" % i] = g(332 + 4 * i), g(348 + 4 * i)
        for i in range(2):
            r["it%d" % i], r["itc%d" % i] = g(372 + 4 * i), g(380 + 4 * i)
        r["name"] = r["id"]
        out.append(r)
    return out


def read_server(path):
    """Серверный LimitationQuest.txt → список словарей FIELDS (числа как есть)."""
    lines = open(path, "rb").read().split(b"\r\n")
    n = int(lines[0].strip())
    rows = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        f = [x.strip() for x in ln.split(b"\t")]
        if len(f) != 32:
            raise SystemExit("%s: строка «%s» — %d полей вместо 32" % (path, ln[:40], len(f)))
        rows.append({k: int(v) for k, v in zip(FIELDS, f)})
    if len(rows) != n:
        raise SystemExit("%s: заголовок %d, строк %d" % (path, n, len(rows)))
    return rows


def server_rows():
    """Числа клиента → серверные строки по правилам шапки (lvMax 99 → 100; 20026 режим 0 — уже у клиента)."""
    rows = read_client()
    for r in rows:
        if r["lvmax"] == 99:
            r["lvmax"] = 100
    return rows


def render(rows):
    """Строки → байты файла (заголовок-число, TAB, CRLF после каждой строки — как у живого файла)."""
    out = [str(len(rows)).encode()]
    for r in rows:
        out.append(b"\t".join(str(r[k]).encode() for k in FIELDS))
    return b"\r\n".join(out) + b"\r\n"


def check(rows, items_path=None):
    """Проверки новой таблицы; возврат списка ошибок (пусто — годно)."""
    err = []
    for k, r in enumerate(rows):
        if r["id"] != 20000 + k:
            err.append("строка %d: номер %d, ожидался %d (загрузчики требуют строго подряд)" % (k, r["id"], 20000 + k))
        if r["type"] not in (0, 1, 2, 3):
            err.append("%d: тип %d" % (r["id"], r["type"]))
        if r["mode"] not in (0, 1):
            err.append("%d: режим %d (GS сдаёт только 0/1)" % (r["id"], r["mode"]))
        if r["type"] != 0 and r["max"] <= 0:
            err.append("%d: тип %d при max %d" % (r["id"], r["type"], r["max"]))
        if not (1 <= r["lvmin"] <= r["lvmax"] <= 100):
            err.append("%d: уровни %d–%d" % (r["id"], r["lvmin"], r["lvmax"]))
        if r["mode"] == 0 and r["req0"] < 0:
            err.append("%d: режим 0 без цели" % r["id"])
        for k2 in ("max", "reqc0", "reqc1", "reqc2", "reqc3", "reqc4", "chc0", "chc1", "chc2", "chc3", "itc0", "itc1"):
            if not (-32768 <= r[k2] <= 32767):
                err.append("%d: %s=%d не влезает в i16" % (r["id"], k2, r[k2]))
    if len(rows) > 200:
        err.append("записей %d > 200 (MAX_LIMITATIONCOUNT)" % len(rows))
    # доски NPC: индексы заданий из Raid_npc_data.BIN должны быть в таблице и равны номеру (BOARD_QUEST_FLOW §2.4)
    b = open(CLIENT_NPC, "rb").read()
    n = struct.unpack_from("<i", b, 4)[0]
    rec = (len(b) - 0x14) // n
    for j in range(n):
        o = 0x14 + rec * j
        if struct.unpack_from("<i", b, o + 4)[0] < 0:
            continue
        for k in range(100):
            q = struct.unpack_from("<i", b, o + 28 + 4 * k)[0]
            if q >= 0 and (k >= len(rows) or rows[k]["id"] != q or q != 20000 + k):
                err.append("Raid_npc_data: NPC-запись %d, индекс %d → %d не совпадает с таблицей" % (j, k, q))
    if items_path:   # каждый предмет таблицы есть в item_table.txt сервера
        have = set()
        for ln in open(items_path, "rb").read().split(b"\r\n")[1:]:
            f = ln.split(b"\t")
            if f and f[0].strip().isdigit():
                have.add(int(f[0].strip()))
        for r in rows:
            for key in ["req%d" % i for i in range(5)] + ["ch%d" % i for i in range(4)] + ["it0", "it1"]:
                if r[key] > 0 and r[key] not in have:
                    err.append("%d: предмет %s=%d отсутствует в item_table.txt сервера" % (r["id"], key, r[key]))
    return err


def patch_ai(data):
    """Monster.ai → копия с условием 20056 у мобов NEW_COND (первый слот обязан быть пуст, флаг +402 = 1)."""
    if len(data) != 850 * REC_AI:
        raise SystemExit("Monster.ai: размер %d, ожидалось %d" % (len(data), 850 * REC_AI))
    out = bytearray(data)
    for k in range(850):
        o = k * REC_AI
        mob = struct.unpack_from("<i", data, o)[0]
        if mob not in NEW_COND:
            continue
        q, item, rate = NEW_COND[mob]
        if data[o + AI_FLAG] != 1:
            raise SystemExit("моб %d: флаг условий +402 = %d, ожидался 1" % (mob, data[o + AI_FLAG]))
        slot = data[o + AI_COND:o + AI_COND + 12]
        if slot != EMPTY_COND:
            raise SystemExit("моб %d: первый слот условия занят (%s) — стоп" % (mob, slot.hex()))
        struct.pack_into("<iBHib", out, o + AI_COND, q, 0, 0, item, rate)
    diff = [i for i in range(len(data)) if data[i] != out[i]]
    if len(diff) > 24 or not diff:
        raise SystemExit("Monster.ai: изменено %d байт (ожидалось ≤ 24)" % len(diff))
    return bytes(out)


def build(items_path=None):
    """Собрать файлы волны в data_board_quest/; код 0 — годно."""
    if md5b(open(CLIENT_BIN, "rb").read()) != CLIENT_MD5:
        raise SystemExit("эталон %s изменился (md5 ≠ %s) — стоп" % (CLIENT_BIN, CLIENT_MD5))
    rows = server_rows()
    err = check(rows, items_path)
    for e in err:
        print("ОШИБКА:", e)
    if err:
        return 3
    data = render(rows)
    if read_server_bytes(data) != rows:
        print("ОШИБКА: перечитанная таблица не равна собранной")
        return 3
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "LimitationQuest.txt")
    open(path, "wb").write(data)
    print("LimitationQuest.txt: %d записей, %d б, md5 %s" % (len(rows), len(data), md5b(data)))
    for base, (src, where) in AI_BASES.items():
        raw = open(src, "rb").read()
        if md5b(raw) != base:
            raise SystemExit("%s: md5 %s ≠ база %s" % (src, md5b(raw), base))
        new = patch_ai(raw)
        dst = os.path.join(OUT, "Monster_%s.ai" % base[:8])
        open(dst, "wb").write(new)
        print("Monster_%s.ai (%s): база %s → %s" % (base[:8], where, base, md5b(new)))
    if os.path.exists(BASE_GS):
        old = {r["id"]: r for r in read_server(BASE_GS)}
        changed = sum(1 for r in rows if r["id"] in old and r != old[r["id"]])
        print("сводка: изменено %d из %d прежних, новых %d (%s)" % (
            changed, len(old), len([r for r in rows if r["id"] not in old]), ", ".join(str(r["id"]) for r in rows if r["id"] not in old)))
    return 0


def read_server_bytes(data):
    """Байты серверной таблицы → строки (для самопроверки render)."""
    import tempfile
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    try:
        open(tmp, "wb").write(data)
        return read_server(tmp)
    finally:
        os.remove(tmp)


def table():
    """Markdown «было → стало» по каждому заданию (было — снимок живой GS-таблицы)."""
    old = {r["id"]: r for r in read_server(BASE_GS)}
    names = {"type": "тип", "max": "max", "zone": "зона", "lvmin": "lvMin", "lvmax": "lvMax", "mode": "режим", "exp": "опыт",
             "gold": "золото"}
    print("| Задание | Изменения (было → стало) |")
    print("|---|---|")
    for r in server_rows():
        o = old.get(r["id"])
        if not o:
            print("| %d | НОВОЕ: тип %d, max %d, зона %d, ур. %d–%d, режим %d, цели %s, опыт %d, золото %d, предметы %s |" % (
                r["id"], r["type"], r["max"], r["zone"], r["lvmin"], r["lvmax"], r["mode"],
                ", ".join("%d×%d" % (r["req%d" % i], r["reqc%d" % i]) for i in range(5) if r["req%d" % i] > 0), r["exp"], r["gold"],
                ", ".join("%d×%d" % (r["it%d" % i], r["itc%d" % i]) for i in range(2) if r["it%d" % i] > 0) or "—"))
            continue
        d = []
        for k in FIELDS:
            if k != "name" and r[k] != o[k]:
                d.append("%s %d → %d" % (names.get(k, k), o[k], r[k]))
        print("| %d | %s |" % (r["id"], "; ".join(d) if d else "без изменений"))


def coverage(ai_path=None):
    """Чем засчитываются цели каждого задания на сервере (по НОВОЙ Monster.ai): режим 0 — условие (задание, предмет) у моба;
    режим 1 — предмет встречается в записи моба вне условий (выпадение; сведения справочные). Возврат: список заданий, у которых
    цель режима 0 не засчитывается никем."""
    data = open(ai_path or os.path.join(OUT, "Monster_c4da0022.ai"), "rb").read()
    cond, drop = {}, {}
    for k in range(len(data) // REC_AI):
        r = data[k * REC_AI:(k + 1) * REC_AI]
        mob = struct.unpack_from("<i", r, 0)[0]
        for e in range(6):
            q, _s, _p, item, rate = struct.unpack_from("<iBHib", r, AI_COND + 12 * e)
            if q >= 20000:
                cond.setdefault((q, item), []).append((mob, rate))
        for o in range(0, AI_COND - 3):
            v = struct.unpack_from("<i", r, o)[0]
            if 20000 < v < 100000:
                drop.setdefault(v, set()).add(mob)
    bad = []
    for r in server_rows():
        goals = [(r["req%d" % i], r["reqc%d" % i]) for i in range(5) if r["req%d" % i] > 0]
        if r["mode"] == 0:
            miss = [g for g, _ in goals if (r["id"], g) not in cond]
            src = "; ".join("%d×%d ← мобы %s" % (g, c, ",".join("%d(%d%%)" % m for m in cond.get((r["id"], g), [])) or "НЕТ") for g, c in goals)
            if miss:
                bad.append(r["id"])
        else:
            src = "; ".join("%d×%d ← выпадение у %s" % (g, c, ",".join(str(m) for m in sorted(drop.get(g, ()))) or "НИКОГО") for g, c in goals)
        print("%d режим %d: %s" % (r["id"], r["mode"], src))
    print("режим 0 без засчёта: %s" % (", ".join(map(str, bad)) or "нет"))
    return bad


def main():
    """Точка входа: build / table / coverage."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "build":
        items = sys.argv[sys.argv.index("--items") + 1] if "--items" in sys.argv else None
        return build(items)
    if cmd == "table":
        table()
        return 0
    if cmd == "coverage":
        coverage()
        return 0
    print(__doc__ or "подкоманды: build [--items <item_table.txt>] | table")
    return 1


if __name__ == "__main__":
    sys.exit(main())
