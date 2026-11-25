// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P14 — длина сообщения чата: 80 -> 160 байт + ЗАКРЫТИЕ ТРЁХ ПЕРЕПОЛНЕНИЙ СТЕКА.
//
//  ЗАЧЕМ (два независимых повода, оба закрываются одним патчем):
//
//  1) ★ БЕЗОПАСНОСТЬ. В трёх обработчиках чата сток копирует тело пакета в
//     стековый `char[80]` БЕЗ какой-либо проверки длины — проверка `<= 80` стоит
//     НИЖЕ по коду, уже после memcpy. Любой модифицированный клиент кладёт туда
//     до ~690 байт и затирает кадр стека вплоть до сохранённого EIP:
//        Recv_NormalChatClient @0x5471A0 (5084)  memcpy(buf80, pkt+9,  packetLen-10)
//        recvGlobalChatClient  @0x547670 (5086)  memcpy(buf80, pkt+36, packetLen-10-27)
//        sub_403F50            @0x403F50 (4120)  memcpy(buf80, pkt+37, (packetLen-10)-28)
//     Сверх того во всех трёх длина считается ЗНАКОВОЙ: короткий пакет даёт
//     отрицательное значение, которое memcpy принимает как size_t ~4 ГБ.
//     Дыры существуют в проде прямо сейчас, независимо от затеи с длиной.
//
//  2) ДЛИНА. Клиентское поле ввода ограничено 68 символами (chat.c:829,
//     ctrlEditSetTextLength(2609, 68)). Пользователь хочет вдвое — 136. Сервер
//     режет всё, что длиннее 80 (сообщение молча не доходит), поэтому подъём
//     клиентского лимита без серверного патча бессмысленен И смертелен (см. п.1).
//
//  ─── ЧТО ИМЕННО ПАТЧИМ (7 функций, не 5 как в ТЗ) ───────────────────────────
//  ТЗ (Reports/chat_context_menu_and_limits.md §7) перечисляло 6 обработчиков
//  клиентских опкодов. Сверка со СТОКОМ показала:
//    • адрес Recv_NormalChatClient в ТЗ ОШИБОЧЕН: 0x547030 — это другая функция
//      (Send_CharAttackMotion, проверяет подпись sub_523F00). Настоящий
//      обработчик 5084 — 0x5471A0;
//    • ТЗ не заметило ДВА обработчика ВХОДЯЩИХ серверных пакетов, у которых
//      тот же гейт `<= 80`. Без них шёпот и чат отряда длиннее 80 байт молча
//      исчезали бы на доставке:
//        sub_547EB0 @0x547EB0 — доставка шёпота  (текст a2-52 -> рассылка 5089)
//        sub_451210 @0x451210 — доставка чата отряда (a2-74 -> рассылка 5106)
//    • обработчик клана 4120 (sub_403F50) НЕ рассылает 4121 клиентам сам —
//      он пересылает пакет соседнему серверу; обратная рассылка идёт из
//      clanChatRes@0x4041E0, где буфер уже 704 байта и гейта `<= 80` НЕТ,
//      патчить его не требуется.
//    • 6718 (чат армии/фракции) НЕ трогаем: пересылка 6719 имеет ФИКСИРОВАННУЮ
//      длину 101 и подписывается MD5 (sub_523F00, 0x6C байт) — изменение размера
//      поля потребовало бы согласованной правки подписи на клиенте. Канал армии
//      остаётся на 80 байтах (рекомендация ТЗ §7.5.2).
//
//  ─── ПОЧЕМУ НЕ «ЗАМЕНА ОБРАБОТЧИКА ЦЕЛИКОМ» (как предлагало ТЗ) ─────────────
//  Реимплементация семи функций (сотни строк с безымянными полями CUser,
//  фильтрами получателей, сторожами циклов и пересылками на четыре смежных
//  процесса) — это семь новых источников расхождения с оригиналом. Вместо этого
//  сделаны 52 ТОЧЕЧНЫЕ правки, каждая со сверкой исходных байтов; логика стока
//  сохраняется байт-в-байт, меняются только (а) место текстового буфера,
//  (б) предел длины, (в) сама проверка. На каждую функцию:
//
//    1. КАДР:   `sub esp, N` -> `sub esp, N + 0x100`   (imm32 на месте, 6 байт)
//    2. БУФЕР:  текстовый `char[80]` переезжает в СВЕЖИЕ 256 байт на дне кадра
//               (ebp-(N+0x100)); переписывается disp32 в каждом `lea` (6 байт,
//               граница инструкции сохраняется). Так буфер получает собственные
//               256 байт и больше НЕ соседствует с sendBody[704].
//               ★ Почему переезд обязателен: в стоке буфер вплотную примыкает к
//               sendBody, а sendBody заполняется заголовком РАНЬШЕ, чем из буфера
//               копируется текст — оставь мы буфер на месте, текст длиннее 80
//               затирался бы собственным заголовком пакета.
//    3. ОЧИСТКА: `call memset` (тот, что чистит текстовый буфер) ->
//               `call AsdaChatClearBuf` — обнуляет все 256 байт (сток чистил 80,
//               а хвост занулялся соседним memset(sendBody) — после переезда
//               соседа нет, и strlen ушёл бы за буфер).
//    4. ДЛИНА:  5-байтовая площадка -> `jmp` в стаб, который ЗАЖИМАЕТ длину
//               в [0..MaxTextLen] ДО любого memcpy (это и есть фикс переполнения)
//               и возвращается в сток.
//    5. ГЕЙТ:   оставшиеся `cmp <len>, 80 / jle` -> `jmp` (1 байт 7E->EB):
//               верхняя граница теперь задаётся зажимом из п.4, который
//               выполняется СТРОГО РАНЬШЕ.
//
//  ─── ПРЕДЕЛ СВЕРХУ = 199 БАЙТ (не выдумано, снято с смежных процессов) ──────
//  Текст едет дальше в RelayServer (сток \\@@ASTORY_SERVER_HOSTNAME@@\...\v2\RelayServer):
//    • клан 4121, обработчик @0x409798: буфер 200 б, проверка 1..200
//      (`sub esi,0x27; lea ecx,[esi-1]; cmp ecx,0xC7; ja отказ`);
//    • отряд 3107 -> общий обработчик @0x40198B: буфер 200 б, проверка
//      (`sub eax,0x28; cmp ax,0xC8; jge отказ` + `cmp cx,0xC7; ja отказ`) = 1..199.
//  ⇒ жёсткий потолок MaxTextLen = 199. Клиент при этом режет ввод по 199
//    (clampedText[200] во всех send-путях) — контур согласован.
//  Запись чата на лог-сервер (3670, ФИКСИРОВАННЫЕ 106 байт) не затрагивается:
//  она копирует из текстового буфера ровно `push 0x50` = 80 байт и продолжает
//  писать 80 (ТЗ §7.5.1) — правки не потребовалось, размер там зашит в push imm8.
//
//  ─── СЧЁТЧИК «МУСОРНЫХ» ПАКЕТОВ ────────────────────────────────────────────
//  Ни одна площадка не находится в диспетчере: управление НИКОГДА не уходит мимо
//  штатного пути, sub_5244B0 не вызывается ни на байт чаще, чем в стоке
//  (опасность ТЗ §7.5.4 к этому патчу неприменима — она была про P13).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

// Действующий предел длины текста чата. До установки P14 — стоковые 80.
// Читает P13 (широкие каналы 6560), чтобы оба патча жили по одному числу.
int g_chatMaxTextLen = Srv::kChatMaxTextStock;

namespace
{
    // Сколько байт резервируем под текстовый буфер на дне кадра. 256 — с запасом
    // над жёстким потолком 199 + завершающий ноль, кратно 4 (выравнивание кадра).
    constexpr DWORD kReserve      = 0x100;
    constexpr int   kMaxTextHard  = 199;   // потолок RelayServer (см. шапку)
    constexpr int   kMaxTextFloor = 40;    // ниже стока опускать бессмысленно

    int  g_maxText   = 160;   // действующий предел (копия g_chatMaxTextLen для asm)
    int  g_maxTextB  = 187;   // g_maxText + 27 — заголовок тела 5086
    int  g_maxTextC  = 188;   // g_maxText + 28 — заголовок тела 4120
    bool g_runtimeLog = true;

    // Адреса возврата стабов (точки стока сразу за занятой площадкой).
    DWORD g_retA = 0x005471C0;   // mov word ptr [ebp-0x3C4], ax
    DWORD g_retB = 0x00547691;   // mov word ptr [ebp-0x3BC], ax
    DWORD g_retC = 0x00403F70;   // mov word ptr [ebp-0x360], ax
    DWORD g_retD = 0x00547C96;   // movsx edx, word ptr [ebp-0x334]
    DWORD g_retE = 0x00451088;   // movsx eax, word ptr [ebp-4]  (проверка > 0)
    DWORD g_retF = 0x00547F76;   // movsx edx, word ptr [ebp-0x33C]
    DWORD g_retG = 0x004512A7;   // movsx edx, word ptr [ebp-4]  (проверка > 0)

    // ── лог обрезаний ───────────────────────────────────────────────────────
    // Срабатывает ТОЛЬКО когда клиент заявил длину больше предела, т.е. на
    // попытке эксплуатации или на клиенте с несогласованным лимитом.
    // Путь холодный, но защищаемся и от флуда, и от гонки потоков.
    CRITICAL_SECTION g_logLock;
    bool             g_logLockReady = false;
    volatile LONG    g_clampCount   = 0;
}

// Вызывается ТОЛЬКО из стабов и ТОЛЬКО в момент фактической обрезки.
extern "C" void __stdcall AsdaChatLenClamped(int opcode, int requested, int limit)
{
    const LONG n = InterlockedIncrement(&g_clampCount);
    if (!g_runtimeLog)                        { return; }
    if (n > 50 && (n % 500) != 0)             { return; }   // антифлуд лога
    if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
    Log::Line(L"[chatlen] * OVERFLOW BLOCKED: op=%d заявлено %d байт при пределе %d "
              L"— обрезано (всего срабатываний: %d)",
              opcode, requested, limit, (int)n);
    if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
}

// Замена memset для ТЕКСТОВОГО буфера: сток чистил 80 байт, нам нужны все 256.
// Сигнатура и соглашение — как у memset (__cdecl, чистит вызывающий).
extern "C" void* __cdecl AsdaChatClearBuf(void* dst, int value, size_t count)
{
    (void)value;
    (void)count;
    memset(dst, 0, kReserve);
    return dst;
}

namespace
{
    // ═══════════════════ стабы зажима длины (по одному на функцию) ═══════════
    //
    //  A/B/C — длина считается в самом начале функции, ДО memcpy: занимаем
    //          площадку вычисления. D/E/F/G — длина уже лежит в word [ebp-4],
    //          а площадкой служит сама проверка `cmp <reg>, 80` + её jcc.

    // A: Recv_NormalChatClient (5084). len = packetLen - 10, зажим в [0..M].
    __declspec(naked) void ClampA()
    {
        __asm
        {
            movsx eax, word ptr [ebp+0Ch]     // packetLen
            sub   eax, 0Ah                    // тело кадра = packetLen - 10
            cmp   eax, g_maxText
            jle   a_low
            pushad
            push  g_maxText
            push  eax
            push  5084
            call  AsdaChatLenClamped
            popad
            mov   eax, g_maxText
        a_low:
            test  eax, eax                    // отрицательная длина -> 0
            jge   a_done
            xor   eax, eax
        a_done:
            jmp   dword ptr [g_retA]
        }
    }

    // B: recvGlobalChatClient (5086). Сохраняется packetLen-10, текст = это -27.
    //    Зажим в [27 .. M+27] -> длина текста в [0 .. M].
    __declspec(naked) void ClampB()
    {
        __asm
        {
            movsx eax, word ptr [ebp+0Ch]
            sub   eax, 0Ah
            mov   ecx, g_maxTextB             // M + 27
            cmp   eax, ecx
            jle   b_low
            pushad
            push  g_maxText
            push  eax
            push  5086
            call  AsdaChatLenClamped
            popad
            mov   eax, ecx
        b_low:
            cmp   eax, 1Bh                    // короче заголовка -> текст 0 байт
            jge   b_done
            mov   eax, 1Bh
        b_done:
            jmp   dword ptr [g_retB]
        }
    }

    // C: sub_403F50 (4120, клан). Сохраняется packetLen-10, текст = это -28.
    //    <= 0 оставляем как есть — сток сам вернётся по проверке `v8 > 0`.
    __declspec(naked) void ClampC()
    {
        __asm
        {
            movsx eax, word ptr [ebp+0Ch]
            sub   eax, 0Ah
            test  eax, eax
            jle   c_done                      // сток вернётся по проверке > 0
            cmp   eax, 1Ch                    // короче заголовка -> текст 0 байт
            jge   c_high
            mov   eax, 1Ch
            jmp   c_done
        c_high:
            mov   ecx, g_maxTextC             // M + 28
            cmp   eax, ecx
            jle   c_done
            pushad
            push  g_maxText
            push  eax
            push  4120
            call  AsdaChatLenClamped
            popad
            mov   eax, ecx
        c_done:
            jmp   dword ptr [g_retC]
        }
    }

    // D/E/F/G — общий вид: зажать word [ebp-4] до M и вернуться в сток.
    //  D: sub_547BD0 (5088, шёпот C->S),   len = packetLen - 31
    //  E: sub_450FB0 (5105, отряд C->S),   len = packetLen - 12
    //  F: sub_547EB0 (доставка шёпота),    len = packetLen - 52
    //  G: sub_451210 (доставка чата отряда), len = packetLen - 74
    __declspec(naked) void ClampD()
    {
        __asm
        {
            movsx eax, word ptr [ebp-4]
            mov   ecx, g_maxText
            cmp   eax, ecx
            jle   d_done
            pushad
            push  ecx
            push  eax
            push  5088
            call  AsdaChatLenClamped
            popad
            mov   word ptr [ebp-4], cx
        d_done:
            jmp   dword ptr [g_retD]
        }
    }

    __declspec(naked) void ClampE()
    {
        __asm
        {
            movsx eax, word ptr [ebp-4]
            mov   ecx, g_maxText
            cmp   eax, ecx
            jle   e_done
            pushad
            push  ecx
            push  eax
            push  5105
            call  AsdaChatLenClamped
            popad
            mov   word ptr [ebp-4], cx
        e_done:
            jmp   dword ptr [g_retE]
        }
    }

    __declspec(naked) void ClampF()
    {
        __asm
        {
            movsx eax, word ptr [ebp-4]
            mov   ecx, g_maxText
            cmp   eax, ecx
            jle   f_done
            pushad
            push  ecx
            push  eax
            push  3106
            call  AsdaChatLenClamped
            popad
            mov   word ptr [ebp-4], cx
        f_done:
            jmp   dword ptr [g_retF]
        }
    }

    __declspec(naked) void ClampG()
    {
        __asm
        {
            movsx eax, word ptr [ebp-4]
            mov   ecx, g_maxText
            cmp   eax, ecx
            jle   g_done
            pushad
            push  ecx
            push  eax
            push  3108
            call  AsdaChatLenClamped
            popad
            mov   word ptr [ebp-4], cx
        g_done:
            jmp   dword ptr [g_retG]
        }
    }

    // ═══════════════════════════ таблица правок ══════════════════════════════
    //
    //  Все адреса сняты дизассемблером ПО НАСТОЯЩЕМУ СТОКУ
    //  GameServer.exe_before_mine_patch.exe (MD5 4e20f0ad…, 1 740 800 б).
    //  Оригинальные байты каждой площадки сверяются перед записью.

    // Ссылка на текстовый буфер: `lea reg, [ebp - bufDisp]` = 8D <modrm> disp32.
    struct BufRef { DWORD va; BYTE modrm; };

    // ── A: Recv_NormalChatClient @0x5471A0, опкод 5084 ──────────────────────
    const BufRef kRefsA[] = {
        { 0x005471E5, 0x8D },   // memset(текст, 0, 0x50)
        { 0x00547219, 0x95 },   // memcpy(текст, pkt+9, len)      ← переполнение
        { 0x005472CA, 0x95 },   // strlen(текст)
        { 0x00547333, 0x95 },   // memcpy(&sendBody[26], текст, chatLen)
        { 0x0054760F, 0x85 },   // memcpy(лог-запись[80], текст, 0x50) — лог 3670
    };
    // ── B: recvGlobalChatClient @0x547670, опкод 5086 ───────────────────────
    const BufRef kRefsB[] = {
        { 0x005476D5, 0x8D }, { 0x0054774A, 0x85 }, { 0x005477E0, 0x8D },
        { 0x00547839, 0x95 }, { 0x00547A27, 0x85 },
    };
    // ── C: sub_403F50 @0x403F50, опкод 4120 (клан) ──────────────────────────
    const BufRef kRefsC[] = {
        { 0x00403FDC, 0x95 }, { 0x00404021, 0x85 }, { 0x00404177, 0x8D },
    };
    // ── D: sub_547BD0 @0x547BD0, опкод 5088 (шёпот) ─────────────────────────
    const BufRef kRefsD[] = {
        { 0x00547C1B, 0x85 }, { 0x00547CD7, 0x95 }, { 0x00547CE6, 0x85 },
        { 0x00547E25, 0x95 },
    };
    // ── E: sub_450FB0 @0x450FB0, опкод 5105 (отряд) ─────────────────────────
    const BufRef kRefsE[] = {
        { 0x00450FFB, 0x85 }, { 0x004510D6, 0x8D }, { 0x004511AA, 0x95 },
    };
    // ── F: sub_547EB0 @0x547EB0, доставка шёпота (S->C 5089) ────────────────
    const BufRef kRefsF[] = {
        { 0x00547EFC, 0x85 }, { 0x00547FA8, 0x85 }, { 0x005481A7, 0x8D },
        { 0x005482CD, 0x95 },
    };
    // ── G: sub_451210 @0x451210, доставка чата отряда (S->C 5106) ───────────
    const BufRef kRefsG[] = {
        { 0x0045125C, 0x85 }, { 0x004512E6, 0x8D }, { 0x0045145E, 0x85 },
    };

    // Оригинальные байты площадок зажима.
    const BYTE kClampOrigABC[7] = { 0x0F, 0xBF, 0x45, 0x0C, 0x83, 0xE8, 0x0A };
    const BYTE kClampOrigD[5]   = { 0x83, 0xF9, 0x50, 0x7E, 0x05 };   // cmp ecx,80 / jle
    const BYTE kClampOrigE[5]   = { 0x83, 0xFA, 0x50, 0x7F, 0x08 };   // cmp edx,80 / jg
    const BYTE kClampOrigF[5]   = { 0x83, 0xF9, 0x50, 0x7E, 0x05 };
    const BYTE kClampOrigG[5]   = { 0x83, 0xF9, 0x50, 0x7F, 0x08 };

    struct FnSpec
    {
        const wchar_t* tag;         // метка в логе
        const wchar_t* what;        // что за обработчик
        DWORD          fnVa;        // вход функции стока
        DWORD          frameVa;     // площадка `sub esp, imm32` (81 EC imm32)
        DWORD          frameSize;   // оригинальный размер кадра
        DWORD          bufDisp;     // оригинальное смещение текстового буфера
        DWORD          clearVa;     // `call memset` для текстового буфера
        DWORD          clampVa;     // площадка стаба зажима
        BYTE           clampLen;
        const BYTE*    clampOrig;
        const void*    clampStub;
        DWORD          bypassVa;    // `jle` гейта `<= 80` (0 = нет)
        const BufRef*  refs;
        int            nrefs;
    };

    const FnSpec kFns[] =
    {
        { L"A", L"5084 общий/крик (Recv_NormalChatClient)",
          0x005471A0, 0x005471A3, 0x3E4, 0x338, 0x005471EC,
          0x005471B9, 7, kClampOrigABC, &ClampA, 0x005472EA, kRefsA, ARRAYSIZE(kRefsA) },

        { L"B", L"5086 глобальный (recvGlobalChatClient)",
          0x00547670, 0x00547673, 0x3D0, 0x338, 0x005476DC,
          0x0054768A, 7, kClampOrigABC, &ClampB, 0x00547800, kRefsB, ARRAYSIZE(kRefsB) },

        { L"C", L"4120 клан (sub_403F50)",
          0x00403F50, 0x00403F53, 0x364, 0x318, 0x00403FE3,
          0x00403F69, 7, kClampOrigABC, &ClampC, 0x00404051, kRefsC, ARRAYSIZE(kRefsC) },

        { L"D", L"5088 шёпот (sub_547BD0)",
          0x00547BD0, 0x00547BD3, 0x378, 0x330, 0x00547C22,
          0x00547C8C, 5, kClampOrigD,   &ClampD, 0x00547D00, kRefsD, ARRAYSIZE(kRefsD) },

        { L"E", L"5105 отряд (sub_450FB0)",
          0x00450FB0, 0x00450FB3, 0x34C, 0x320, 0x00451002,
          0x00451083, 5, kClampOrigE,   &ClampE, 0,          kRefsE, ARRAYSIZE(kRefsE) },

        { L"F", L"доставка шёпота -> 5089 (sub_547EB0)",
          0x00547EB0, 0x00547EB3, 0x374, 0x338, 0x00547F03,
          0x00547F6C, 5, kClampOrigF,   &ClampF, 0,          kRefsF, ARRAYSIZE(kRefsF) },

        { L"G", L"доставка чата отряда -> 5106 (sub_451210)",
          0x00451210, 0x00451213, 0x390, 0x338, 0x00451263,
          0x004512A2, 5, kClampOrigG,   &ClampG, 0,          kRefsG, ARRAYSIZE(kRefsG) },
    };

    // ── сборка ожидаемых оригинальных байтов ────────────────────────────────
    void MakeFrameOrig(DWORD size, BYTE out[6])
    {
        out[0] = 0x81; out[1] = 0xEC;                       // sub esp, imm32
        out[2] = (BYTE)( size        & 0xFF);
        out[3] = (BYTE)((size >>  8) & 0xFF);
        out[4] = (BYTE)((size >> 16) & 0xFF);
        out[5] = (BYTE)((size >> 24) & 0xFF);
    }

    void MakeLeaOrig(BYTE modrm, DWORD disp, BYTE out[6])
    {
        const INT32 d = -(INT32)disp;
        out[0] = 0x8D; out[1] = modrm;                      // lea reg, [ebp+disp32]
        out[2] = (BYTE)( d        & 0xFF);
        out[3] = (BYTE)((d >>  8) & 0xFF);
        out[4] = (BYTE)((d >> 16) & 0xFF);
        out[5] = (BYTE)((d >> 24) & 0xFF);
    }

    void MakeCallOrig(DWORD siteVa, DWORD target, BYTE out[5])
    {
        const INT32 rel = (INT32)(target - (siteVa + 5));
        out[0] = 0xE8;
        out[1] = (BYTE)( rel        & 0xFF);
        out[2] = (BYTE)((rel >>  8) & 0xFF);
        out[3] = (BYTE)((rel >> 16) & 0xFF);
        out[4] = (BYTE)((rel >> 24) & 0xFF);
    }

    // Хранилище сгенерированных эталонов на время сверки (52 площадки).
    BYTE g_origBuf[64][8];
    Site g_sites[64];
    int  g_siteCount = 0;

    void AddSite(DWORD va, const BYTE* bytes, SIZE_T len)
    {
        if (g_siteCount >= (int)ARRAYSIZE(g_sites)) { return; }
        if (len > sizeof(g_origBuf[0])) { return; }
        for (SIZE_T i = 0; i < len; ++i) { g_origBuf[g_siteCount][i] = bytes[i]; }
        g_sites[g_siteCount].va   = va;
        g_sites[g_siteCount].orig = g_origBuf[g_siteCount];
        g_sites[g_siteCount].len  = len;
        ++g_siteCount;
    }
}

PatchResult P14_ChatMessageLength()
{
    const wchar_t* S = L"P14_ChatMessageLength";
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }

    // ── настройки ───────────────────────────────────────────────────────────
    const bool fixOnly = Config::GetBool(S, L"FixOverflowOnly", false);
    int maxText = Config::GetInt(S, L"MaxTextLen", 160);
    if (fixOnly)
    {
        maxText = Srv::kChatMaxTextStock;      // только закрыть переполнения
    }
    if (maxText < kMaxTextFloor)
    {
        Log::Line(L"    P14: MaxTextLen=%d меньше допустимого %d — поднято до стоковых %d",
                  maxText, kMaxTextFloor, Srv::kChatMaxTextStock);
        maxText = Srv::kChatMaxTextStock;
    }
    if (maxText > kMaxTextHard)
    {
        Log::Line(L"    P14: MaxTextLen=%d выше потолка смежных процессов (RelayServer "
                  L"принимает не больше %d байт текста) — понижено до %d",
                  maxText, kMaxTextHard, kMaxTextHard);
        maxText = kMaxTextHard;
    }
    g_maxText        = maxText;
    g_maxTextB       = maxText + 27;
    g_maxTextC       = maxText + 28;
    g_chatMaxTextLen = maxText;                // им же пользуется P13 (6560)
    g_runtimeLog     = Config::GetBool(S, L"RuntimeLog", true);

    if (!g_logLockReady)
    {
        InitializeCriticalSection(&g_logLock);
        g_logLockReady = true;
    }

    // ── сверка ВСЕХ площадок ────────────────────────────────────────────────
    g_siteCount = 0;
    for (const FnSpec& f : kFns)
    {
        BYTE tmp[6];
        MakeFrameOrig(f.frameSize, tmp);
        AddSite(f.frameVa, tmp, 6);

        for (int i = 0; i < f.nrefs; ++i)
        {
            MakeLeaOrig(f.refs[i].modrm, f.bufDisp, tmp);
            AddSite(f.refs[i].va, tmp, 6);
        }

        MakeCallOrig(f.clearVa, Srv::kMemset, tmp);
        AddSite(f.clearVa, tmp, 5);

        AddSite(f.clampVa, f.clampOrig, f.clampLen);

        if (f.bypassVa)
        {
            const BYTE jle = 0x7E;
            AddSite(f.bypassVa, &jle, 1);
        }
    }

    if (!VerifyAllSites(L"P14", g_sites, g_siteCount)) { return PatchResult::Mismatch; }

    // ── запись ──────────────────────────────────────────────────────────────
    // ★ ПОРЯДОК ВАЖЕН и выбран так, чтобы ЛЮБОЙ обрыв на середине оставлял
    //   сервер в безопасном состоянии:
    //     1) зажим длины   — сразу закрывает переполнение (дальше можно не успеть);
    //     2) очистка буфера — безобидна и до, и после переезда;
    //     3) кадр + ссылки  — переезд буфера;
    //     4) снятие гейта `<= 80` — ПОСЛЕДНИМ: только оно разрешает длину > 80,
    //        поэтому до него сервер ведёт себя как сток, но уже без дыр.
    for (const FnSpec& f : kFns)
    {
        const DWORD newFrame = f.frameSize + kReserve;
        const DWORD newDisp  = newFrame;              // буфер = самое дно кадра

        BYTE tmp[6];
        if (!Hook::WriteJmp (f.clampVa, f.clampStub, f.clampLen)) { return PatchResult::Failed; }
        if (!Hook::WriteCall(f.clearVa, &AsdaChatClearBuf, 5))    { return PatchResult::Failed; }

        MakeFrameOrig(newFrame, tmp);
        if (!Hook::WriteBytes(f.frameVa, tmp, 6)) { return PatchResult::Failed; }

        for (int i = 0; i < f.nrefs; ++i)
        {
            MakeLeaOrig(f.refs[i].modrm, newDisp, tmp);
            if (!Hook::WriteBytes(f.refs[i].va, tmp, 6)) { return PatchResult::Failed; }
        }

        if (f.bypassVa)
        {
            // 7E (jle) -> EB (jmp short): верхнюю границу теперь задаёт зажим
            if (!Hook::WriteByteChecked(f.bypassVa, 0x7E, 0xEB)) { return PatchResult::Failed; }
        }

        Log::Line(L"    P14 %s: %s — кадр 0x%03X->0x%03X, текст [ebp-0x%03X] (%d б), "
                  L"очистка @0x%08X, зажим @0x%08X (%d б) -> стаб 0x%08X, "
                  L"гейт<=80 @0x%08X, ссылок на буфер: %d",
                  f.tag, f.what, f.frameSize, newFrame, newDisp, kReserve,
                  f.clearVa, f.clampVa, (int)f.clampLen, (DWORD)f.clampStub,
                  f.bypassVa, f.nrefs);
    }

    Log::Line(L"    P14: предел текста чата %d байт (сток 80, потолок смежных процессов %d); "
              L"каналы 5084/5086/4120/5088/5105 + доставка 5089/5106; "
              L"6718 (армия) намеренно оставлен на 80; запись лога 3670 по-прежнему 80 б; "
              L"клиентское поле ввода 2609 должно быть ограничено НЕ БОЛЕЕ чем %d символами "
              L"(наш порт ставит 136), обрезаний с момента старта: %d",
              g_maxText, kMaxTextHard, g_maxText, (int)g_clampCount);
    return PatchResult::Applied;
}
