// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P46 — ЗАКРЫТИЕ ПЕРЕПОЛНЕНИЯ СТЕКА в обработчике «крика» личной лавки (опкод 6316).
//
//  ★ БЕЗОПАСНОСТЬ. Обработчик Recv_SelfStoreGlobalChat @0x508B40 (6316 «крик
//    лавки» → рассылка 5087) копирует тело пакета в стековый char[80] БЕЗ
//    какой-либо проверки длины — проверка длины пакета (a3 < 700) и предел
//    strlen < 80 стоят НИЖЕ по коду, уже ПОСЛЕ memcpy. Декомпил
//    (RE/ida/server_work/GameServer.c, Recv_SelfStoreGlobalChat):
//
//        char  Str[80];     // [ebp-0x338]
//        _BYTE v17[708];    // [ebp-0x2E8]  (sendBody, ВПЛОТНУЮ за Str)
//        ...
//        memcpy(Str, (a4 + 36), (__int16)(a3 - 10) - 27);   // ← БЕЗ проверки
//        ...
//        if (a3 < 700 && a3 > 0) {                           // поздно (после copy)
//            if (strlen(Str) < 80 && strlen(Str) > 0) {      // поздно (после copy)
//                ... рассылка 5087 ...
//
//    Длина копии = (a3 − 10) − 27, где a3 (packetLen) — ЗНАКОВЫЙ __int16.
//    Это ТОТ ЖЕ класс дефекта, что P14 закрыл для чата 5084/5086/4120; в список
//    P14 функция 6316 не вошла (проверено по исходнику p14_chat_message_length.cpp
//    и доке chat-message-length-x2.md). Два независимых вектора:
//      • длинное тело  — до ~660 байт затирают Str[80], соседний sendBody и кадр
//        стека вплоть до /GS-куки и сохранённого EIP;
//      • короткое тело — (a3−10)−27 становится ОТРИЦАТЕЛЬНЫМ, memcpy принимает его
//        как size_t ≈ 4 ГБ.
//
//  ─── ЧТО ПАТЧИМ (ОДНА площадка, минимально) ─────────────────────────────────
//  В отличие от P14 предел НЕ поднимается: «крик лавки» остаётся на стоковых 80
//  байтах (клиент режет ввод до 79). Поэтому НЕ нужны ни переезд буфера, ни
//  снятие гейта `< 80` — достаточно ЗАЖАТЬ длину копии ДО memcpy так, чтобы в
//  80-байтовый Str всегда писалось не больше 80 байт.
//
//    Площадка 0x508B59 (7 байт `0F BF 45 0C 83 E8 0A` = `movsx eax,[ebp+0xC];
//    sub eax,0x0A`) — вычисление (a3 − 10), результат уходит в `mov word
//    [ebp-0x348], ax` @0x508B60 и ЕДИНСТВЕННО там же читается как длина memcpy
//    (0x508BDE: `movsx edx,[ebp-0x348]; sub edx,0x1B; push edx`). Заменяем 7 байт
//    на `jmp` в стаб, который приводит (a3 − 10) к [0x1B .. 0x1B+80] и
//    возвращается в сток на 0x508B60. Тогда:
//      • текст копии ∈ [0 .. 80] — Str[80] не переполняется НИКОГДА;
//      • короткий/отрицательный пакет → длина 0 (сток дальше отсеет по `> 0`);
//      • ЛЕГАЛЬНЫЙ пакет (текст ≤ 79, т.е. a3−10 ≤ 0x6A) проходит стаб БЕЗ
//        изменений — поведение байт-в-байт как в стоке;
//      • пакет с текстом ровно 80 (a3−10 = 0x6B) копируется как 80 байт, но
//        sendBody обнулён ДО копии (memset @0x508BC1), так что strlen(Str) = 80 и
//        стоковый гейт `< 80` его штатно ОТБРАСЫВАЕТ — как и в оригинале.
//    Гейт `< 80` (0x508D95) и предел пакета `< 700` (0x508D5E) НЕ трогаются:
//    стоковое поведение приёма/отказа сохранено полностью.
//
//  ─── ОХВАТ (правило no-scope-cutting + false-negatives-method) ──────────────
//  Сплошной скан .text на идиому «длина = packetLen−10» (`0F BF 45 0C 83 E8 0A`)
//  дал РОВНО: 0x403F50 (4120), 0x5471A0 (5084), 0x547670 (5086) — все три уже
//  закрыты P14 — плюс 0x508B40 (6316, эта функция) и 0x54D710 (приёмник
//  рейтинговых званий: (packetLen−10) делится на 13 для подсчёта ФИКСИРОВАННЫХ
//  записей, тело в стек НЕ копируется — не этот класс). Прочие обработчики текста
//  (6313 @0x507930, 6302 @0x502E50, 5200 @0x4924F0, 6718 @0x466FF4, 6080 и др.)
//  защищены MD5-подписью ФИКСИРОВАННОЙ длины тела (sub_523F00) и копируют
//  фиксированное число байт — не переполняются (у 6316 вызова sub_523F00 НЕТ).
//  ⇒ 6316 — единственный незакрытый представитель класса; P46 закрывает ровно его.
//
//  ─── СЧЁТЧИК «МУСОРНЫХ» ПАКЕТОВ / ПОТОК УПРАВЛЕНИЯ ───────────────────────────
//  Единственная правка лежит ВНУТРИ самого обработчика; управление в диспетчер
//  мимо штатного пути не уходит, sub_5244B0 не вызывается ни на байт чаще стока.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    // Нижняя граница (a3 − 10): короче заголовка «крика» (27 байт) → текст 0.
    constexpr int   kLoBound   = 0x1B;          // 27
    // Стоковый предел текста. Лавку оставляем на 80 (клиент режет до 79).
    constexpr int   kTextLimit = 80;

    int   g_hiBound  = kLoBound + kTextLimit;    // 0x1B + 80 = 0x6B (верх. граница a3−10)
    bool  g_runtimeLog = true;                   // писать строку при фактической обрезке

    // Адрес возврата в сток: `mov word ptr [ebp-0x348], ax` сразу за площадкой.
    DWORD g_retStoreShout = 0x00508B60;

    // ── лог обрезаний ────────────────────────────────────────────────────────
    // Срабатывает ТОЛЬКО когда клиент заявил длину больше стокового предела — то
    // есть на попытке переполнения или на рассинхроне лимита с клиентом. Путь
    // холодный; защита и от флуда, и от гонки потоков (как в P14).
    CRITICAL_SECTION g_logLock;
    bool             g_logLockReady = false;
    volatile LONG    g_clampCount   = 0;
}

// Вызывается ТОЛЬКО из стаба и ТОЛЬКО в момент фактической обрезки длины.
// requested = (a3 − 10) из пакета; limitValue = верхняя граница (a3 − 10) = 0x1B+80.
extern "C" void __stdcall AsdaStoreShoutClamped(int requested, int limitValue)
{
    const LONG n = InterlockedIncrement(&g_clampCount);
    if (!g_runtimeLog)                        { return; }
    if (n > 50 && (n % 500) != 0)             { return; }   // антифлуд лога
    if (g_logLockReady) { EnterCriticalSection(&g_logLock); }
    Log::Line(L"[storechat6316] * OVERFLOW BLOCKED: op=6316 текст %d байт при пределе %d "
              L"— обрезано (всего срабатываний: %d)",
              requested - kLoBound, limitValue - kLoBound, (int)n);
    if (g_logLockReady) { LeaveCriticalSection(&g_logLock); }
}

namespace
{
    // Стаб зажима длины. Занимает площадку вычисления (a3 − 10) на 0x508B59
    // (7 байт), приводит её к [kLoBound .. g_hiBound] и возвращается в сток на
    // g_retStoreShout, где значение кладётся в word [ebp-0x348] = длина memcpy.
    // Клобберит eax (его ждёт возврат) и edx; ecx/edx сток дальше не читает
    // (ближайшее обращение к edx — `movsx edx,[ebp-0x348]` @0x508BDE, уже заново).
    // ★ Граница грузится в EDX (`8B 15` — префикс стаба уникален: у P14 ClampA
    //   `3B 05`, ClampB `8B 0D`, ClampC `85 C0`), чтобы locator verify_dll.py
    //   различал стабы по сигнатуре без неоднозначности.
    __declspec(naked) void ClampStoreShout()
    {
        __asm
        {
            movsx eax, word ptr [ebp+0Ch]     // packetLen (a3), как в стоке
            sub   eax, 0Ah                    // a3 - 10,       как в стоке
            mov   edx, g_hiBound              // верхняя граница (a3-10) = 0x1B+80
            cmp   eax, edx                    // > 0x1B+80 ?  (слишком длинный)
            jle   s_lo
            pushad
            push  edx                         // limitValue  (2-й аргумент)
            push  eax                         // requested   (1-й аргумент)
            call  AsdaStoreShoutClamped
            popad
            mov   eax, g_hiBound              // зажать сверху
        s_lo:
            cmp   eax, 1Bh                    // < 27 (короче заголовка) ?
            jge   s_done
            mov   eax, 1Bh                    // → текст 0 (сток отсеет по `> 0`)
        s_done:
            jmp   dword ptr [g_retStoreShout]
        }
    }

    // Оригинальные 7 байт площадки (сверяются перед записью).
    const BYTE kClampOrig[7] = { 0x0F, 0xBF, 0x45, 0x0C, 0x83, 0xE8, 0x0A };

    Site g_sites[1];
}

PatchResult P46_StoreShoutOverflow()
{
    const wchar_t* S = L"P46_StoreShoutOverflow";
    if (!Config::GetBool(S, L"Enabled", true))
    {
        return PatchResult::Disabled;
    }
    g_runtimeLog = Config::GetBool(S, L"RuntimeLog", true);

    if (!g_logLockReady)
    {
        InitializeCriticalSection(&g_logLock);
        g_logLockReady = true;
    }

    // ── сверка площадки ───────────────────────────────────────────────────────
    g_sites[0].va   = 0x00508B59;
    g_sites[0].orig = kClampOrig;
    g_sites[0].len  = sizeof(kClampOrig);
    if (!VerifyAllSites(L"P46", g_sites, 1)) { return PatchResult::Mismatch; }

    // ── запись: 7-байтовая площадка -> jmp в стаб (5 б jmp + 2 nop) ────────────
    if (!Hook::WriteJmp(0x00508B59, &ClampStoreShout, sizeof(kClampOrig)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P46: 6316 (крик лавки, Recv_SelfStoreGlobalChat @0x508B40) — "
              L"длина копии зажата в [%d..%d] байт ДО memcpy @0x508BF7; предел текста "
              L"остаётся стоковым %d (гейт strlen<80 и предел пакета<700 не тронуты); "
              L"обрезаний с момента старта: %d",
              0, kTextLimit, kTextLimit, (int)g_clampCount);
    return PatchResult::Applied;
}
