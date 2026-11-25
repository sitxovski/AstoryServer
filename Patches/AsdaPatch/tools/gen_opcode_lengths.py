# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# gen_opcode_lengths.py — ГЕНЕРАТОР ТАБЛИЦЫ ДЛИН КАДРОВ ПО ОПКОДУ для P55 (общий валидатор пакетов,
# античит В4, мера 8 плана `Reports/anticheat/00_PLAN.md`).
#
# Источник — ТОЛЬКО декомпил GameServer (`RE/ida/server_work/GameServer.c`, база = живой образ e7b4ac38):
#   1) диспетчер клиентских пакетов sub_42A9D0: `case 0x…:` / `if ( v4 == N )` → вызов обработчика с кадром a3;
#   2) в обработчике (и, если там пусто, в вызываемых им функциях, которым передан кадр) — вызов
#      sub_523F00(pkt, LEN, userNum, SECRET): LEN = длина тела под MD5, SECRET = 1 → 8-байтный секрет есть.
# Кадр (CopyToWriteBuffer@0x5656D0 / GetReadBuffer@0x42A6B0): 0xFB, WORD size(+1, ВЕСЬ кадр, 1..700),
#   WORD +3, WORD userNum(+5, ставит сервер), WORD opcode(+7), [8 секрет], 16 MD5, тело, 0xFE (size-1).
#   sub_523F00: при SECRET=1 MD5 читается с +17, тело с +33; при 0 — MD5 с +9, тело с +25.
#   ⇒ minSize = 9 + (8·SECRET) + 16 + LEN + 1; клиентский паддинг (CNetwork_Send, a6=1: (+11)%20)
#   ⇒ допустимый диапазон [minSize, minSize+19] (01_network_protocol.md §4).
# Опкоды без sub_523F00 (чат и др.) — ручная таблица MANUAL ниже, каждая строка со ссылкой на декомпил.
# Классы для token-bucket — таблица CLASSES ниже (по обработчикам), иначе «прочее».
#
# Запуск: py -3.13 gen_opcode_lengths.py [GameServer.c] [OpcodeLengths.h] [coverage.md]
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "..", "..", "RE", "ida", "server_work", "GameServer.c")
OUT_H = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "src", "OpcodeLengths.h")
OUT_MD = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "..", "..", "..", "..", "Reports", "anticheat", "wave_A4_opcode_lengths.md")

OP_MAX = 0x2B00          # опкоды клиента 0..0x2AFF (дерево диспетчера: > 0x2AFE → только 20000)
HDR, SECRET, MD5, TAIL, PAD = 9, 8, 16, 1, 19
FRAME_MAX = 0x2BC        # предел размера кадра в CopyToWriteBuffer (700)

# ── классы опкодов (token-bucket): номер → имя; порядок = enum OpClass в p55 ──────────────────────
CLASS_NAMES = ["прочее", "движение", "бой/навыки", "чат", "предметы/торговля", "тяжёлые-БД", "GM"]
C_OTHER, C_MOVE, C_COMBAT, C_CHAT, C_ITEM, C_DB, C_GM = range(7)

# Явные классы по опкоду (приоритет над эвристикой по имени обработчика).
CLASS_BY_OPCODE = {
    # движение / позиция
    4006: C_MOVE, 4008: C_MOVE, 4010: C_MOVE, 4032: C_MOVE, 4034: C_MOVE, 4050: C_DB,
    # чат (все без MD5; пределы — P14/P46/P13)
    5084: C_CHAT, 5086: C_CHAT, 5088: C_CHAT, 5105: C_CHAT, 4120: C_CHAT, 6316: C_CHAT, 6560: C_CHAT,
    6028: C_GM, 6029: C_GM, 6718: C_CHAT,
    # тяжёлые запросы к базе (логон/портал/создание/удаление персонажа, склад, покупка, аукцион, почта)
    4001: C_DB, 5058: C_DB, 4124: C_DB, 4156: C_DB, 5070: C_DB, 5020: C_DB, 20000: C_DB,
    9901: C_DB, 9903: C_DB, 9905: C_DB, 9907: C_DB, 9909: C_DB, 9915: C_DB,
}
# Эвристика по имени обработчика (подстрока, без учёта регистра) → класс.
CLASS_BY_NAME = [
    ("Operator", C_GM), ("_GM", C_GM), ("Command_Call", C_GM), ("CountDown", C_GM), ("MapBlock", C_GM),
    ("TargetJump", C_GM), ("Tutorial", C_OTHER),
    ("Move", C_MOVE), ("Stop", C_MOVE), ("Jump", C_MOVE), ("Teleport", C_MOVE), ("Portal", C_MOVE),
    ("Attack", C_COMBAT), ("Skill", C_COMBAT), ("Battle", C_COMBAT), ("Target", C_COMBAT), ("Duel", C_COMBAT),
    ("Chat", C_CHAT), ("Whisper", C_CHAT), ("Shout", C_CHAT),
    ("Item", C_ITEM), ("Inven", C_ITEM), ("Shop", C_ITEM), ("Store", C_ITEM), ("Trade", C_ITEM), ("Exchange", C_ITEM),
    ("Auction", C_ITEM), ("TransAction", C_ITEM), ("Gacha", C_ITEM), ("Upgrade", C_ITEM), ("Craft", C_ITEM),
    ("Warehouse", C_DB), ("Logon", C_DB), ("Create", C_DB), ("Delete", C_DB), ("Mail", C_DB), ("Post", C_DB),
]

# ── РУЧНАЯ таблица: опкоды без sub_523F00 (каждая строка — ссылка на декомпил) ───────────────────
#   opcode: (minSize, maxSize или 0 = «верх не проверять», пояснение)
MANUAL = {
    1000:  (26, 26 + PAD, "пинг: диспетчер сам зовёт sub_523F00(a3, 0, a2, 0) → 9+16+0+1"),
    # ★ 12.10 живой журнал: клиент порта шлёт payload 27 б (кадр 61: 9 + 8 секрет + 16 MD5 + 27 + 1), сервер копирует
    #   0x1D=29 б с +33 — последние 2 байта читаются за кадром (нули буфера), вход работает. Нижняя граница = 61.
    20000: (61, 63 + PAD, "AcceptEx: диспетчер копирует 0x1D б с +33 (memcpy(v24, a3+33, 0x1D)) без MD5; порт шлёт 27 б payload → кадр 61"),
    # ★ 12.10 живой журнал: 5256/6158 — переменная длина: 31 б шапка + 29 б на цель, до 20 целей (порт SendSkillUseBody,
    #   сервер memcpy(&v30+29*i, arg4+29*i+40, 0x1D) GS:45946; без пада, a6=0) → кадр 41 … 41+29*20.
    5256:  (41, 41 + 29 * 20, "RecvChar_SkillUse: 9+8+16+(31−24)... список целей 29 б × ≤20 (GS:45946), без пада"),
    6158:  (41, 41 + 29 * 20, "RecvChar_SkillUse_0 (страж): та же раскладка списка целей, без пада"),
    5084:  (11, 0, "Recv_NormalChatClient@0x5471A0: текст с +9, длина packetLen-10 (>0) — без MD5; предел P14"),
    5086:  (38, 0, "recvGlobalChatClient@0x547670: 0x1B б с +9, текст с +36, длина packetLen-37 — без MD5; предел P14"),
    5088:  (32, 0, "sub_547BD0 (шёпот): a3-31 (>0), имя с +9, текст далее — без MD5; предел P14"),
    5105:  (13, 0, "sub_450FB0 (чат отряда): a3-12 (>0), <=80 — без MD5; предел P14"),
    4120:  (11, 0, "sub_403F50 (чат клана): a3-10 (>0) — без MD5; предел P14"),
    6316:  (38, 0, "Recv_SelfStoreGlobalChat@0x508B40: 0x1B б с +9, текст с +36, (a3-10)-27 — без MD5; зажим P46"),
    6560:  (12, 0, "P13 (наш обработчик, в стоке default): bodyLen = packetLen-10 >= 2 — без MD5; предел P14"),
    # ★ P79 24.10.2026 [ИСПРАВЛЕНИЕ таблицы]: прежняя запись (253, 0) описывала РЕЖИМ 1 sub_499A30 (ответ DBManager 2243,
    #   memcpy 0xF3), а клиентский 2244 — режим 0, тела не читает. Клиент (эталон antiCheat_SendBitMaskCheck@security.c:2121
    #   и порт SendSoulmateOldPartnerReq2244) шлёт конверт с секретом: 8 секрет + 16 MD5, payload 0, с падом → 34..53.
    #   Живой журнал P55 (Mode=0) 19–22.10: 6 ложных «кадр короче минимума» с размерами 40..53.
    2244:  (HDR + SECRET + MD5 + TAIL, HDR + SECRET + MD5 + TAIL + PAD,
            "sub_499A30@0x499A30 (соулмейт, режим 0 — клиент): тело не читается; клиент шлёт секрет 8 + MD5 16, payload 0 → 9+8+16+0+1, пад"),
    4156:  (18, 0, "FriendMemberList_Req@0x4025C0: секрет 8 б с +9 (sub_524390), MD5 нет → 9+8+1"),
    5422:  (48, 48 + PAD, "SoulJar_ResponseUser_Res: секрет с +9, memcpy(v9, a2+33, 0xE) без MD5 → 33+14+1"),
    6035:  (18, 0, "Recv_OperatorCommand_Invincible@0x5518A0: секрет 8 б с +9, MD5 нет → 9+8+1"),
    6036:  (18, 0, "Recv_OperatorCommand_GetValue: секрет 8 б с +9, MD5 нет → 9+8+1"),
}
# Переопределение LEN там, где сток проверяет не то, что шлёт клиент (аргумент sub_523F00 в декомпиле ≠ кадр клиента).
LEN_OVERRIDE = {
    # P49: сток сверяет MD5 5450 по 0x89 = 137 б (`push 0x89` @0x4ED8CF), клиент (эталон и порт) подписывает
    # и шлёт 0x101 = 257 б тела; P49 правит длину на 0x101. Без переопределения кадр 291 б попал бы в «длиннее max».
    5450: (0x101, "P49: клиент шлёт 0x101 б (сток сверял 0x89)"),
}

NOT_HANDLERS = {
    "sub_52EEA0", "sub_523F00", "memcpy", "memset", "sprintf", "OutputDebugStringA", "InterlockedIncrement",
    "GetTickCount", "QueryPerformanceCounter", "sub_5244B0", "sub_569DF0", "sub_532570", "sub_42FA50",
    "AcceptExUser", "sub_5271F0", "sub_527310", "sub_419C10", "GetReadBuffer", "sub_5328F0", "sub_5324A0",
    "sub_52ECF0", "sub_52ED50", "sub_5324F0",
}


def load_functions(path):
    """{имя: (адрес, текст функции)} по маркерам `//---- name @ 0xADDR ----`."""
    text = open(path, encoding="utf-8", errors="replace").read()
    parts = re.split(r"^//---- (\S+) @ (0x[0-9A-Fa-f]+) ----\s*$", text, flags=re.M)
    funcs = {}
    for i in range(1, len(parts), 3):
        funcs[parts[i]] = (int(parts[i + 1], 16), parts[i + 2])
    return funcs


RE_CASE = re.compile(r"^\s*case (0x[0-9A-Fa-f]+|\d+)u?:\s*$")
RE_IF = re.compile(r"^\s*(?:else )?if \( v4 == (\d+) \)\s*$")
# Обе формы декомпила: sub_523F00(pkt, LEN, userNum, SEC) и sub_523F00(this, pkt, LEN, userNum, SEC).
RE_SIGN = re.compile(r"sub_523F00\([^;]*?,\s*(0x[0-9A-Fa-f]+|\d+)u?,\s*\(?\s*[A-Za-z_]\w*\s*\)?\s*,\s*(\d)\s*\)")
RE_CALL = re.compile(r"\b([A-Za-z_]\w*)\(")


def num(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def dispatcher_bodies(disp_text):
    """[(opcodes[], body_text)] — тело каждой ветки диспетчера."""
    lines = disp_text.splitlines()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        m = RE_CASE.match(lines[i])
        if m:
            ops = [num(m.group(1))]
            i += 1
            while i < n and RE_CASE.match(lines[i]):
                ops.append(num(RE_CASE.match(lines[i]).group(1)))
                i += 1
            body = []
            while i < n and not RE_CASE.match(lines[i]) and not re.match(r"^\s*default:", lines[i]):
                body.append(lines[i])
                if re.match(r"^\s*(break;|goto LABEL_\d+;)\s*$", lines[i]):
                    i += 1
                    break
                i += 1
            out.append((ops, "\n".join(body)))
            continue
        m = RE_IF.match(lines[i])
        if m:
            op = int(m.group(1))
            i += 1
            depth = 0
            body = []
            if i < n and lines[i].strip() == "{":
                depth = 1
                i += 1
                while i < n and depth > 0:
                    depth += lines[i].count("{") - lines[i].count("}")
                    if depth > 0:
                        body.append(lines[i])
                    i += 1
            else:
                body.append(lines[i])
                i += 1
            out.append(([op], "\n".join(body)))
            continue
        i += 1
    return out


def calls_in(body):
    return [c for c in RE_CALL.findall(body) if c not in NOT_HANDLERS and not c.startswith("LABEL")]


def signs_in(text):
    return [(num(m.group(1)), int(m.group(2))) for m in RE_SIGN.finditer(text)]


def packet_param(func_text, call_line, funcs_name):
    """Имя параметра обработчика, в который передан кадр a3 диспетчера (по позиции аргумента)."""
    m = re.search(re.escape(funcs_name) + r"\((.*)\);", call_line)
    if not m:
        return None
    args = split_args(m.group(1))
    try:
        pos = [a.strip() for a in args].index("a3")
    except ValueError:
        pos = next((k for k, a in enumerate(args) if re.search(r"\ba3\b", a)), None)
        if pos is None:
            return None
    sig = re.search(r"^[^\n]*\b" + re.escape(funcs_name) + r"\((.*?)\)\s*$", func_text, flags=re.M)
    if not sig:
        return None
    params = split_args(sig.group(1))
    if pos >= len(params):
        return None
    pm = re.search(r"([A-Za-z_]\w*)\s*$", params[pos].strip())
    return pm.group(1) if pm else None


def split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def find_signs(funcs, fname, pkt_param, depth=0, seen=None):
    """Вызовы sub_523F00 в обработчике; если нет — в функциях, которым он передаёт кадр (глубина ≤ 2)."""
    seen = seen if seen is not None else set()
    if fname in seen or fname not in funcs:
        return [], None
    seen.add(fname)
    text = funcs[fname][1]
    s = signs_in(text)
    if s:
        return s, fname
    if depth >= 2 or not pkt_param:
        return [], None
    for line in text.splitlines():
        for callee in RE_CALL.findall(line):
            if callee in NOT_HANDLERS or callee == fname or callee not in funcs:
                continue
            if not re.search(r"\b" + re.escape(pkt_param) + r"\b", line):
                continue
            sub_param = packet_param_generic(funcs[callee][1], line, callee, pkt_param)
            r, where = find_signs(funcs, callee, sub_param, depth + 1, seen)
            if r:
                return r, where
    return [], None


def packet_param_generic(func_text, call_line, callee, pkt_param):
    m = re.search(re.escape(callee) + r"\((.*)\)", call_line)
    if not m:
        return None
    args = split_args(m.group(1))
    pos = next((k for k, a in enumerate(args) if re.search(r"\b" + re.escape(pkt_param) + r"\b", a)), None)
    if pos is None:
        return None
    sig = re.search(r"^[^\n]*\b" + re.escape(callee) + r"\((.*?)\)\s*$", func_text, flags=re.M)
    if not sig:
        return None
    params = split_args(sig.group(1))
    if pos >= len(params):
        return None
    pm = re.search(r"([A-Za-z_]\w*)\s*$", params[pos].strip())
    return pm.group(1) if pm else None


def classify(op, handler):
    if op in CLASS_BY_OPCODE:
        return CLASS_BY_OPCODE[op]
    h = (handler or "").lower()
    for key, cls in CLASS_BY_NAME:
        if key.lower() in h:
            return cls
    return C_OTHER


def main():
    funcs = load_functions(SRC)
    disp = funcs["sub_42A9D0"][1]
    entries = {}      # op → dict(min, max, secret, len, handler, src, variable)
    unknown = {}      # op → handler (без sub_523F00)
    for ops, body in dispatcher_bodies(disp):
        inline = signs_in(body)
        handler, where, signs = None, None, []
        if inline:
            signs, where, handler = inline, "диспетчер", "(inline)"
        for c in calls_in(body):
            if c in funcs:
                handler = handler if handler and handler != "(inline)" else c
                if not signs:
                    line = next((l for l in body.splitlines() if re.search(r"\b" + re.escape(c) + r"\(", l)), "")
                    pp = packet_param(funcs[c][1], line, c)
                    signs, where = find_signs(funcs, c, pp)
                    if signs:
                        handler = c
                        break
        for op in ops:
            if op in MANUAL:
                mn, mx, note = MANUAL[op]
                entries[op] = dict(min=mn, max=mx, secret=-1, len=-1, handler=handler or "(диспетчер)", src="MANUAL: " + note, variable=mx == 0)
                continue
            if signs:
                lens = sorted(set(signs))
                ln, sec = lens[0]
                if op in LEN_OVERRIDE:
                    ln = LEN_OVERRIDE[op][0]
                    where = "%s; LEN переопределён: %s" % (where, LEN_OVERRIDE[op][1])
                mn = HDR + (SECRET if sec else 0) + MD5 + ln + TAIL
                variable = len(lens) > 1
                mx = 0 if variable else mn + PAD
                entries[op] = dict(min=mn, max=mx, secret=sec, len=ln, handler=handler, src=where, variable=variable,
                                   forms=lens)
            else:
                unknown[op] = handler or "(нет вызова с кадром)"
    for op, (mn, mx, note) in MANUAL.items():
        if op not in entries:
            entries[op] = dict(min=mn, max=mx, secret=-1, len=-1, handler="(вне дерева)", src="MANUAL: " + note, variable=mx == 0)
    for op in entries:
        entries[op]["cls"] = classify(op, entries[op]["handler"])

    # ── OpcodeLengths.h ──────────────────────────────────────────────────────
    ops_sorted = sorted(entries)
    h = []
    h.append("// OpcodeLengths.h — СГЕНЕРИРОВАНО tools/gen_opcode_lengths.py из декомпила GameServer.c (не править руками).")
    h.append("// P55 (валидатор пакетов): минимальный/максимальный размер кадра по опкоду и класс для token-bucket.")
    h.append("//   minSize = 9 заголовок + 8 секрет (если есть) + 16 MD5 + LEN (аргумент sub_523F00) + 1 хвост;")
    h.append("//   maxSize = minSize + 19 (паддинг клиента (+11)%%20); 0 = верх не проверять (переменная длина / чат).")
    h.append("//   Опкоды, которых нет в таблице (index 0) — длина неизвестна, валидатор длину НЕ проверяет.")
    h.append("#pragma once")
    h.append("#include <windows.h>")
    h.append("")
    h.append("namespace OpLen")
    h.append("{")
    h.append("    enum OpClass : BYTE { " + ", ".join("k%s = %d" % (n, i) for i, n in enumerate(
        ["Other", "Move", "Combat", "Chat", "Item", "Db", "Gm"])) + " };")
    h.append("    constexpr int kClassCount = 7;")
    h.append("    constexpr int kOpcodeMax  = 0x%X;   // индекс покрывает опкоды 0..0x%X" % (OP_MAX, OP_MAX - 1))
    h.append("    constexpr int kFrameMax   = %d;     // предел кадра CopyToWriteBuffer" % FRAME_MAX)
    h.append("    struct Info { WORD opcode; WORD minSize; WORD maxSize; BYTE secret; BYTE cls; const char* handler; };")
    h.append("    // secret: 1 — конверт с 8-байтным секретом, 0 — без, 255 — ручная запись (без MD5).")
    h.append("    constexpr Info kInfo[] =")
    h.append("    {")
    h.append("        { 0, 0, 0, 0, 0, nullptr },   // [0] = неизвестный опкод")
    for op in ops_sorted:
        e = entries[op]
        sec = 255 if e["secret"] < 0 else e["secret"]
        tag = " // формы LEN %s" % e["forms"] if e.get("forms") and len(e["forms"]) > 1 else ""
        if e["secret"] < 0:
            tag = " // " + e["src"]
        h.append("        { %5d, %3d, %3d, %3d, %d, \"%s\" },%s" % (op, e["min"], e["max"], sec, e["cls"], e["handler"], tag))
    h.append("    };")
    h.append("    constexpr int kInfoCount = %d;" % (len(ops_sorted) + 1))
    # 20000 (AcceptEx) лежит выше индекса 0..0x2AFF — отдельная константа, гейт проверяет его особо.
    h.append("    constexpr int kIndexAcceptEx = %d;   // запись опкода 20000 (вне индекса kIndex)" % (ops_sorted.index(20000) + 1 if 20000 in entries else 0))
    h.append("")
    h.append("    // Индекс по опкоду → номер в kInfo (0 = неизвестно). %d записей." % OP_MAX)
    h.append("    constexpr WORD kIndex[kOpcodeMax] =")
    h.append("    {")
    idx = [0] * OP_MAX
    for k, op in enumerate(ops_sorted):
        if op < OP_MAX:
            idx[op] = k + 1
    for row in range(0, OP_MAX, 32):
        h.append("        " + ",".join("%d" % v for v in idx[row:row + 32]) + ",")
    h.append("    };")
    h.append("}")
    with open(OUT_H, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(h) + "\n")

    # ── покрытие ────────────────────────────────────────────────────────────
    all_ops = sorted(set(entries) | set(unknown))
    known = [op for op in all_ops if op in entries]
    md = []
    md.append("# Таблица длин кадров по опкоду (P55) — покрытие\n")
    md.append("Источник: `%s`. Опкодов в дереве диспетчера sub_42A9D0: **%d**; с известной длиной: **%d** "
              "(из sub_523F00: %d, ручных: %d); без длины (не проверяются): **%d**.\n"
              % (os.path.basename(SRC), len(all_ops), len(known),
                 sum(1 for op in known if entries[op]["secret"] >= 0), sum(1 for op in known if entries[op]["secret"] < 0),
                 len(unknown)))
    md.append("Классы: " + ", ".join("%d=%s" % (i, n) for i, n in enumerate(CLASS_NAMES)) + ".\n")
    md.append("| опкод | обработчик | LEN | секрет | min | max | класс | где найден |")
    md.append("|---|---|---|---|---|---|---|---|")
    for op in all_ops:
        if op in entries:
            e = entries[op]
            md.append("| %d | `%s` | %s | %s | %d | %s | %s | %s |" % (
                op, e["handler"], e["len"] if e["len"] >= 0 else "—", "да" if e["secret"] == 1 else ("нет" if e["secret"] == 0 else "—"),
                e["min"], e["max"] or "не проверять", CLASS_NAMES[e["cls"]],
                (e["src"] + (" (формы %s)" % e["forms"] if e.get("forms") and len(e["forms"]) > 1 else ""))))
        else:
            md.append("| %d | `%s` | — | — | — | — | — | **длина неизвестна** |" % (op, unknown[op]))
    md.append("")
    by_cls = {}
    for op in known:
        by_cls.setdefault(entries[op]["cls"], []).append(op)
    md.append("## По классам\n")
    for c in range(len(CLASS_NAMES)):
        md.append("- %s: %d — %s" % (CLASS_NAMES[c], len(by_cls.get(c, [])), ", ".join(str(x) for x in by_cls.get(c, []))))
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print("опкодов в дереве: %d, с длиной: %d, без длины: %d → %s, %s" % (len(all_ops), len(known), len(unknown), OUT_H, OUT_MD))
    for op in sorted(unknown):
        print("  без длины: %d %s" % (op, unknown[op]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
