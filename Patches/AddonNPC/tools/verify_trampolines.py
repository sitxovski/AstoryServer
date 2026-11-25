# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# verify_trampolines.py — СВЕРКА МАШИННОГО КОДА ПЛОЩАДОК В СОБРАННОЙ AddonNPC.dll.
#
# ЗАЧЕМ (дорогой урок 24.08.2026)
#   Живой NpcServer упал через пять минут после включения правок. Причина — не логика, а
#   КОДИРОВАНИЕ: во встроенном ассемблере MSVC операнд `[reg + имя]`, где `имя` — это
#   C++-константа (`const`/`constexpr`), собирается как ССЫЛКА НА ПАМЯТЬ. В машинный код
#   попадает АДРЕС переменной, а не её значение:
#
#       было в исходнике:  test byte ptr [eax + kStateBits], 1     ; kStateBits = 0x7654
#       собралось:         test byte ptr [eax + 6de892a0], 1       ; адрес константы в DLL
#
#   Компилятор не ругается, сборка проходит, всё выглядит правильно — и падает на первом же
#   вызове. Дамп указал ровно на эту инструкцию.
#
#   Лечение в коде: смещения во встроенном ассемблере задавать ТОЛЬКО через `#define` —
#   препроцессор подставит литерал ещё до ассемблера.
#   Лечение в процессе: вот этот скрипт. Он читает СОБРАННУЮ DLL и сверяет байты каждой
#   площадки с эталоном. Прогонять ПЕРЕД каждой выкладкой.
#
# ЗАПУСК
#   python verify_trampolines.py [путь\AddonNPC.dll]
#   По умолчанию берёт ..\out\AddonNPC.dll. Код возврата 0 — всё сошлось.
import os
import re
import sys

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# Имя площадки -> (обязательные последовательности, запрещённые последовательности)
# Обязательные: то, что ДОЛЖНО быть в машинном коде (правильные смещения).
# Запрещённые: формы, в которые вырождается ошибка со ссылкой на память.
EXPECT = [
    ("N03 запись 0 пуста?",      "6683bd787a0000ff",  "cmp word ptr [ebp+7A78h], 0FFFFh"),
    ("N03 порог из записи 0",    "8bb5847a0000",      "mov esi, [ebp+7A84h]"),
    ("N04 биты состояния",       "f68054760000 01",   "test byte ptr [eax+7654h], 1"),
    ("N04 флаг смерти",          "80b8718f000001",    "cmp byte ptr [eax+8F71h], 1"),
    ("N04 снятие аргумента",     "c20400",            "ret 4"),
    ("N05 текущее здоровье",     "8b8b85780000",      "mov ecx, [ebx+7885h]"),
    ("N05 вычет накопителя",     "2b8b48860000",      "sub ecx, [ebx+8648h]"),
    ("N05 зажим в ноль",         "7902 33c9",         "jns +2 / xor ecx, ecx"),
    ("N06 кандидат не найден?",  "6683f9ff",          "cmp cx, 0FFFFh"),
    ("N06 порог из кандидата",   "0fbfd181c2a8070000c1e2048b143a",
                                 "movsx edx,cx / add edx,7A8h / shl edx,4 / mov edx,[edx+edi]"),
    # N11 (P39) — скрытый оператор невидим для монстров
    ("N11 A состояние цели",     "508b86547600 0085c0",  "push eax / mov eax,[esi+7654h] / test eax,eax"),
    ("N11 B/C/D сост. игрока",   "508b87547600 0085c0",  "push eax / mov eax,[edi+7654h] / test eax,eax"),
    ("N11 бит скрытия",          "a802",                 "test al, 2"),
    # N12 (доводка P39) — угроза к скрытому не возникает, одиночный навык мимо
    ("N12 H массив игроков",     "8b9148770000",         "mov edx, [ecx+7748h]"),
    ("N12 H бит скрытия",        "f684025476000002",     "test byte ptr [edx+eax+7654h], 2"),
    ("N12 H снятие 3 арг.",      "c20c00",               "ret 0Ch"),
    ("N12 H исходные инстр.",    "53558bd8668b44240c",   "push ebx / push ebp / mov ebx,eax / mov ax,[esp+0Ch]"),
    ("N12 I цель-игрок?",        "80bec491000000",       "cmp byte ptr [esi+91C4h], 0"),
    ("N12 I бит скрытия",        "f684035476000002",     "test byte ptr [ebx+eax+7654h], 2"),
    ("N12 I исходная инстр.",    "0fbe967c8f0000",       "movsx edx, byte ptr [esi+8F7Ch]"),
    ("N12 шаг записи игрока",    "69c0a80a0100",         "imul eax, eax, 10AA8h"),
    # ★ N10 ред. 2 (26.10.2026, слот P90): очередь уронов [кадр+1Ch] = [esp+44h] в стабе (24h pushad/pushfd + 4 адрес
    #   возврата). Первая редакция читала [esp+40h] = сохранённый `edi` (указатель this) — запрещённая форма ниже.
    ("N10 очередь уронов",       "609c 8d442444 50 e8",  "pushad / pushfd / lea eax,[esp+44h] / push eax / call N10_QueueSum"),
    ("N10 номер игрока",         "0fb78d64780000",       "movzx ecx, word ptr [ebp+7864h]"),
    ("N10 ист. инстр. площ. 1",  "9d61 668b8b94760000 c3", "popfd / popad / mov cx,[ebx+7694h] / ret"),
    ("N10 ист. инстр. площ. 2",  "9d61 668b4c241a c3",   "popfd / popad / mov cx,[esp+1Ah] / ret"),
    ("N10 крит: бит 31 снят",    "25ffffff7f",           "and eax, 7FFFFFFFh"),
    # ★ N20 (26.10.2026, слот P90): доля урона отряда — поле урона [кадр+18h] = [esp+40h] после pushfd/pushad/адреса возврата.
    ("N20 поле урона, монстр",   "9c60 ff742440 55 e8",  "pushfd / pushad / push [esp+40h] / push ebp / call N20_Clamp"),
    ("N20 исходные инструкции",  "619d 8b54241c 6bf653 c3", "popad / popfd / mov edx,[esp+1Ch] / imul esi,esi,53h / ret"),
    ("N20 максимум здоровья",    "387a0000",             "+7A38h (монстр +31288)"),
    # ★ N23 (04.11.2026, слот P104): скрытый навыком — литеральные смещения во врезках S1–S4.
    ("N23 S1 сток: цель мертва", "80be5878000001",       "cmp byte ptr [esi+7858h], 1"),
    ("N23 скрыт навыком (esi)",  "80be3f17000001",       "cmp byte ptr [esi+173Fh], 1"),
    ("N23 S2 запись цели",       "668993587a0000 9c",    "mov word ptr [ebx+7A58h], dx / pushfd"),
    ("N23 S3 запись цели",       "66899f587a0000 9c",    "mov word ptr [edi+7A58h], bx / pushfd"),
    ("N23 S4 вид цели навыка",   "9c 80bec491000001",    "pushfd / cmp byte ptr [esi+91C4h], 1"),
    ("N23 S4 сохр. eax pushad",  "8944241c 61",          "mov [esp+1Ch], eax / popad"),
    ("N23 S4 запись цели навыка", "668986c5910000 9d c3", "mov word ptr [esi+91C5h], ax / popfd / ret"),
    ("N23 S6 запись цели",       "668983587a0000 61 c3", "mov word ptr [ebx+7A58h], ax / popad / ret"),
]

# ★ 26.10.2026: формы, которых в DLL быть НЕ ДОЛЖНО (повтор ошибки первой редакции N10 — чтение указателя this).
FORBID = [
    ("N10 ред. 1: [esp+40h] как удар 1", "609c33f68b442440", "pushad / pushfd / xor esi,esi / mov eax,[esp+40h]"),
]

# Смещения, которых в площадках быть НЕ ДОЛЖНО: похоже на адрес внутри модуля,
# а не на смещение поля в записи монстра (те все < 0x10000).
SUSPECT_DISP_MIN = 0x00010000


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "out", "AddonNPC.dll")
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        print("НЕТ файла: %s" % path)
        return 1
    d = open(path, "rb").read()
    print("файл: %s (%d б)" % (path, len(d)))
    print()

    bad = 0
    for name, hexpat, asm in EXPECT:
        pat = bytes.fromhex(hexpat.replace(" ", ""))
        hits = [m.start() for m in re.finditer(re.escape(pat), d)]
        if hits:
            print("  [OK] %-24s %s" % (name, asm))
        else:
            bad += 1
            print("  [!!] %-24s НЕ НАЙДЕНО: %s" % (name, asm))
            print("       ожидались байты %s" % pat.hex(" "))
    for name, hexpat, asm in FORBID:   # ★ 26.10.2026: повтор известной ошибки — провал
        pat = bytes.fromhex(hexpat.replace(" ", ""))
        if pat in d:
            bad += 1
            print("  [!!] %-24s ЗАПРЕЩЁННАЯ ФОРМА НАЙДЕНА: %s" % (name, asm))
        else:
            print("  [OK] %-24s нет запрещённой формы (%s)" % (name, asm))

    # Отдельно ловим саму ошибку: обращение к памяти по большому смещению в наших формах.
    print()
    print("Поиск подозрительных смещений (признак ссылки на переменную вместо числа):")
    found = 0
    for opc, txt in ((b"\xf6\x80", "test byte ptr [eax+disp32]"),
                     (b"\x80\xb8", "cmp byte ptr [eax+disp32]"),
                     (b"\x8b\x8b", "mov ecx, [ebx+disp32]"),
                     (b"\x2b\x8b", "sub ecx, [ebx+disp32]"),
                     (b"\x8b\xb5", "mov esi, [ebp+disp32]"),
                     (b"\x8b\x86", "mov eax, [esi+disp32]"),
                     (b"\x8b\x87", "mov eax, [edi+disp32]"),
                     (b"\x8b\x91", "mov edx, [ecx+disp32]"),
                     (b"\x80\xbe", "cmp byte ptr [esi+disp32]")):
        for m in re.finditer(re.escape(opc), d):
            o = m.start() + 2
            if o + 4 > len(d):
                continue
            disp = int.from_bytes(d[o:o + 4], "little")
            if disp >= SUSPECT_DISP_MIN:
                # Отсеиваем случайные совпадения байт в данных: смотрим только те места,
                # где рядом стоят наши характерные окончания.
                tail = d[o + 4:o + 7]
                if tail[:1] in (b"\x01", b"\xc3", b"\x79", b"\x74", b"\x75"):
                    found += 1
                    print("  [!!] %#x: %s disp=%#x  байты %s"
                          % (m.start(), txt, disp, d[m.start():m.start() + 8].hex(" ")))
    if found == 0:
        print("  чисто — подозрительных смещений в наших формах нет")

    print()
    if bad or found:
        print("*** ПРОВЕРКА НЕ ПРОЙДЕНА: выкладывать НЕЛЬЗЯ ***")
        return 2
    print("проверка пройдена: машинный код площадок совпадает с эталоном")
    return 0


if __name__ == "__main__":
    sys.exit(main())
