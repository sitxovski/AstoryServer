// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P49 — ★ ВОЗВРАТ ШТАТНЫХ ПРОВЕРОК ОРИГИНАЛА (мера 11 плана античита, волна А0, 2026-10-12).
//  Отчёт: `Reports/anticheat/wave_A0.md` §3; документ: `AstoryServer/Docs/GameServer/original-checks-p49.md`.
//
//  ── 1. КИК ЗА ПОВТОРЫ (SecretRepeatKick) ──
//  sub_524440@0x524440 (зовёт CheckDisConnectUser@0x526C20 для каждого онлайна): если счётчик
//  ошибок анти-повтора CUser+4 (растит SecretCheck sub_524390 на каждом пакете с немонотонным
//  токеном) > 20 — пишет «Secret Error Disconnect…!» в Log_Secret, обнуляет счётчик и …
//  ВОЗВРАЩАЕТ 0 (обе ветки сходятся на `xor eax,eax` 0x52449D). Вызывающий на 1 кикает
//  («CheckDisConnectUser() Secret Broken Count», 4101 код 3) — ветка мертва.
//  Правка: площадка 0x524496 (7 б `mov dword [eax+4],0` — только ветка «> 20») → стаб:
//  тот же сброс счётчика + eax = 1 + переход на эпилог 0x52449F (мимо `xor eax,eax`).
//  Ветка «≤ 20» (jle → 0x52449D) не тронута. Порог 20 — стоковый.
//  Порт проверен: генератор токена FillAntiReplaySecret монотонен; в живом Log_Secret последняя
//  ошибка 07.08.2026 (1 шт.), с тех пор 0 при регулярной игре (Loginfo 08.10…11.10).
//
//  ── 2. ПОДПИСЬ 5450 (FunctionItemMd5Full) ──
//  Char_FunctionItem_Use@0x4ED780 сверяет MD5 по 0x89 = 137 байтам тела (`push 0x89` @0x4ED8CF),
//  а клиент (эталон netSendItemUsePacket@0xA0D470, network.c: `Net_Md5Digest16(…, usePacket,
//  0x101)`; порт SendFunctionItemUse5450 — так же) подписывает ВСЕ 0x101 = 257 байт. Несходимость
//  вшита в оригинал, поэтому на живом стоял чужой обход P08 («проверка всегда прошла»).
//  Правка: длина сверки 0x89 → 0x101 (5 б `68 89000000` → `68 01010000`), протокол прежний:
//  подпись снова проверяется и сходится с тем, что шлёт клиент. При включении P08 уступает
//  (не ставится) — см. p08_functionitem_check_off.cpp. Чтение 257 б из буфера пакета диспетчера
//  (4096 б, [ebp-0x1048]) — в пределах буфера.
//
//  Площадки (перебор кодировок по .text стока: переходов внутрь 0; с P01…P48 не пересекаются;
//  байты одинаковы в стоке и обоих живых образах):
//     0x00524496  C7 40 04 00 00 00 00   (7 б) → стаб SecretKickStub
//     0x004ED8CF  68 89 00 00 00         (5 б) → 68 01 01 00 00
//  ★ sec2 (2026-10-15): стаб кика за повторы запоминает счётчик Secret ДО сброса (P49_TakeSecretPre) — P48 по нему решает, вызван ли
//  кик нарушениями целостности пакетов P55 (такой кик не засчитывается). Площадки и байты не менялись.
//  ★ sec2c (2026-10-15, ревизия SEC2 Н-3): значение «до сброса» хранится ПО CUser, а не одной парой на процесс. CheckDisConnectUser
//  (0x526C20) зовёт RunProcess объекта нити карт (sub_4C0EA0 из sub_4BEDF0) — нитей несколько, глобалы на процесс: нить B
//  перетирала пару между записью и взятием нити A → P49_TakeSecretPre(A) = −1 → кик A засчитывался ошибочно. Теперь таблица
//  открытой адресации по указателю CUser (CAS захвата слота); запись и взятие одного CUser — в одной нити (стаб → Send_DisConnectType).
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    DWORD g_retSecretKick = 0x0052449F;   // эпилог sub_524440 (`mov esp,ebp; pop ebp; ret 4`)
    // ★ sec2c (Н-3): значение счётчика Secret перед сбросом — ПО CUser (для P48/P55: доля нарушений P55 в кике за повторы).
    //   Открытая адресация, kSecretSlots слотов (степень двойки), хеш (ptr >> 4) & (N − 1), линейный пробинг. Слот, однажды
    //   захваченный CUser (CAS nullptr → CUser), за ним и остаётся: CUser — элементы фиксированного массива 550 записей
    //   m_lpsCharUserInfo (sub_4A1FF0), различных указателей ≤ 550 < N — таблица не переполняется. Ключи не удаляются: CAS
    //   user → nullptr при взятии рвал бы цепочку пробинга для CUser, захвативших слот позже. «Значения нет» — pre = −1.
    constexpr int kSecretSlots = 1024;
    struct SecretSlot { void* volatile user; volatile LONG pre; };   // ключ (CUser*) и значение Secret до сброса (−1 — нет)
    SecretSlot g_secretTab[kSecretSlots] = {};

    // Хеш указателя CUser → стартовый слот пробинга (шаг записей массива 0x40BA0 кратен 16 — сдвиг на 4 различий не теряет).
    inline int SecretHash(const void* user) { return (int)(((DWORD)(DWORD_PTR)user >> 4) & (kSecretSlots - 1)); }

    // Стаб: запомнить счётчик Secret до сброса для этого CUser (перезаписывает прежнее невзятое значение). cdecl — зовётся из asm.
    void __cdecl P49_NoteSecretPre(void* user, LONG pre)
    {
        if (!user) { return; }
        const int h = SecretHash(user);
        for (int i = 0; i < kSecretSlots; ++i)
        {
            SecretSlot& e = g_secretTab[(h + i) & (kSecretSlots - 1)];
            void* cur = e.user;
            if (!cur)
            {
                cur = InterlockedCompareExchangePointer((PVOID volatile*)&e.user, user, nullptr);
                if (!cur) { cur = user; }                          // слот захвачен этим CUser
            }
            if (cur == user) { InterlockedExchange(&e.pre, pre); return; }
        }
        // Таблица полна (при ≤ 550 CUser невозможно) — значение не сохраняется; P48 прочтёт счётчик из CUser, как до sec2.
    }

    // Ветка «> 20»: eax = CUser*. Сток: обнулить счётчик и вернуть 0. Мы: обнулить и вернуть 1.
    __declspec(naked) void SecretKickStub()
    {
        __asm
        {
            pushad                                 // ★ sec2c: запомнить счётчик до сброса по CUser (регистры и флаги сохраняются)
            pushfd
            push  dword ptr [eax+4]                // pre
            push  eax                              // user
            call  P49_NoteSecretPre
            add   esp, 8
            popfd
            popad
            mov   dword ptr [eax+4], 0            // вытеснено: сброс счётчика (как в стоке)
            mov   eax, 1                           // «нарушитель» → CheckDisConnectUser кикнет
            jmp   dword ptr [g_retSecretKick]
        }
    }

    const BYTE kOrigSecret[7] = { 0xC7, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const BYTE kOrigMd5Len[5] = { 0x68, 0x89, 0x00, 0x00, 0x00 };
    const BYTE kNewMd5Len[5]  = { 0x68, 0x01, 0x01, 0x00, 0x00 };
}

// ★ sec2/sec2c: счётчик Secret до сброса стабом для этого CUser (−1 — не было). Берётся один раз (значение → −1, слот за CUser остаётся).
int P49_TakeSecretPre(const BYTE* user)
{
    if (!user) { return -1; }
    const int h = SecretHash(user);
    for (int i = 0; i < kSecretSlots; ++i)
    {
        SecretSlot& e = g_secretTab[(h + i) & (kSecretSlots - 1)];
        void* cur = e.user;
        if (!cur) { return -1; }                                   // конец цепочки — этот CUser не записывался
        if (cur == (void*)user) { return (int)InterlockedExchange(&e.pre, -1); }
    }
    return -1;
}

// Общая точка для P08: включён ли «MD5 5450 по всем 257 байтам» (тогда обход P08 не ставится).
bool P49_FunctionItemMd5FullWanted()
{
    return Config::GetBool(L"P49_OriginalChecksRestore", L"Enabled", true)
        && Config::GetBool(L"P49_OriginalChecksRestore", L"FunctionItemMd5Full", true);
}

PatchResult P49_OriginalChecksRestore()
{
    const wchar_t* S = L"P49_OriginalChecksRestore";
    if (!Config::GetBool(S, L"Enabled", true)) { return PatchResult::Disabled; }
    const bool secretKick = Config::GetBool(S, L"SecretRepeatKick", true);
    const bool md5Full    = Config::GetBool(S, L"FunctionItemMd5Full", true);

    const Site sites[] =
    {
        { 0x00524496, kOrigSecret, sizeof(kOrigSecret) },
        { 0x004ED8CF, kOrigMd5Len, sizeof(kOrigMd5Len) },
    };
    if (!VerifyAllSites(L"P49", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }

    if (secretKick && !Hook::WriteJmp(0x00524496, &SecretKickStub, sizeof(kOrigSecret)))
    {
        return PatchResult::Failed;
    }
    if (md5Full && !Hook::WriteBytes(0x004ED8CF, kNewMd5Len, sizeof(kNewMd5Len)))
    {
        return PatchResult::Failed;
    }

    Log::Line(L"    P49: SecretRepeatKick=%d (кик «Secret Broken Count» при > 20 ошибках анти-повтора), "
              L"FunctionItemMd5Full=%d (5450: MD5 по 0x101 вместо 0x89; обход P08 %s)",
              secretKick ? 1 : 0, md5Full ? 1 : 0, md5Full ? L"не ставится" : L"по своему ключу");
    return PatchResult::Applied;
}
