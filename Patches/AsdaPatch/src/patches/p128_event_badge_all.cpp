// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P128 — ЗНАЧОК СОБЫТИЯ Event.dat ВСЕМ ИГРОКАМ (шаг А5.10 админ-центра, 21.11.2026; слово владельца «Да, делай патч»). [ИСПРАВЛЕНИЕ]
//  Документ: AstoryServer/Docs/GameServer/event-badge-all-p128.md; отчёт: Reports/admin_center/impl_a5_live_20261121.md §«А5.10».
//
//  ── ДЕФЕКТ СТОКА ──
//   Событие Event.dat (тип 0 «добыча и золото» — множитель ШАНСОВ дропа и золота, sub_42E3A0 NpcServer; тип 1 «опыт» — fEvent
//   NpcServer) работает на всех, а значок видит только оператор: ответ 6039 / 6041 NpcServer GameServer отдаёт лишь ему
//   (recvOperatorCommandEventSet@0x552000 / recvOperatorCommandEventOff@0x5522C0 — sub_4C28F0 одному userNum из тела +5); зеркало
//   GameServer (sub_417800 / sub_417B40, массивы 0x5E2348…0x5E2BA0, раскладка Event.dat 2200 б: 13 массивов × 100 = 2 типа × 50 карт)
//   клиентам не уходит; AlarmGameServerEventInfo@0x5585D0 (4301, клиент спрашивает один раз при входе в мир) копирует 16 б запроса
//   клиента и ставит вид 1 только при найденной строке GameServerEvent.txt (★ ревизия 49 Н-4: иначе вид — байт запроса клиента, у
//   Astory 0). Итог — у игроков значок золота (Drop_Buff*, монеты) не горит никогда, значок опыта события — тоже.
//
//  ── ЧТО ДЕЛАЕТ ──
//   На такте каждого игрока в мире (общая точка UserTick 0x526CEB, P73_OnCheckUser → P128_OnUserTick, ~1 с) — сравнить, что
//   ДОЛЖЕН видеть игрок на своей карте (номер карты потока [[mgr+4]+0x4950], как P127), с тем, что ему уже послано, и при разнице
//   послать 6039 (включено, вид, множитель, окно) или 6041 (выключено) — те же тела, что сток шлёт оператору (30 / 16 б). Отсюда сразу:
//   включение / выключение командой (зеркало меняется на приходе 6039/6041 от NpcServer — все 3 GameServer, проверено md5 Event.dat
//   21.11), вход в мир, смена карты, начало и конец окна по часам. Окно «идёт» — как у NpcServer: s_time ≤ ММДДччмм < e_time по
//   GetLocalTime (sub_42E3A0 / sub_437A30 :41279). Пакет — только при изменении (без нагрузки).
//   Опыт: множитель значка = значение события + счастливый час GameServerEvent.txt (сейчас — первая строка, как GetExpUpDownValue) —
//   ровно тот рейт, что получит игрок; у клиента Astory одно поле множителя опыта на оба канала (ApplyEventSet / 4301), поэтому
//   выключение опыта — только если значок опыта зажёг сам P128 (иначе погас бы значок счастливого часа из 4301), а при конце события
//   во время счастливого часа — 6039 с ×(1 + час).
//   ★ ревизия 49 С-1: первый такт НОВОГО входа (новое соединение слота — портал Astory, перезаход; возврат в мир; другой персонаж)
//   шлёт явное состояние обоих видов: идёт — 6039, нет — 6041 (опыт при идущем часе — 6039 ×(1 + час)), потому что клиент прежней
//   версии значок при смене карты не сбрасывает. Н-3: новое соединение узнаётся по поколению слота (g_gen, +1 в P128_OnConnFlag).
//   Ограничение (ревизия 49 Н-2): предметное событие NpcServer «собрали предметы» (flt_47D324, 1 ч) подменяет опыт Event.dat в
//   NpcServer — его GameServer не видит, значок тогда показывает значение Event.dat, а не рейт предметного события.
//   Клиент Astory (AsdaNetSubsystem_RecvWorld.cpp:930) на 6039/6041 только зажигает/гасит значок (UAsdaEffectsSubsystem::ApplyEventSet),
//   строку в чат НЕ печатает (её печатал оригинальный клиент Recv_EventSet@0xF4BAD0 — им не играют).
//  Откат: [P128_EventBadgeAll] Enabled=0 — ничего не шлётся (значок снова только у оператора).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P128_EventBadgeAll";

    constexpr int kSlots      = 0x226;     // userNum 0…549 (как P127)
    constexpr int kOffUserIdx = 0x174;     // CUser: учётка
    constexpr int kOffCharSlot = 0x18C;    // CUser: слот персонажа
    constexpr int kOffInWorld = 0x2E;      // CUser: 1 — в мире
    constexpr int kOffThread  = 4;         // CUserManager+4 → поток карты
    constexpr int kOffMapIdx  = 0x4950;    // поток+0x4950 → номер карты
    constexpr int kMaps       = 50;        // слотов Event.dat на тип

    // зеркало Event.dat в GameServer (загрузчик sub_4190E0, запись sub_417800 / sub_417B40)
    constexpr DWORD kSMon = 0x005E2348, kSDay = 0x005E23B0, kSHour = 0x005E2418, kSMin = 0x005E2480, kSTime = 0x005E24E8;
    constexpr DWORD kEMon = 0x005E2678, kEDay = 0x005E26E0, kEHour = 0x005E2748, kEMin = 0x005E27B0, kETime = 0x005E2818;
    constexpr DWORD kValue = 0x005E29A8, kMinLv = 0x005E2B38, kMaxLv = 0x005E2BA0;
    // счастливые часы GameServerEvent.txt
    constexpr DWORD kLuckyCnt = 0x005A7964, kLuckyYear = 0x005E23AC, kLuckyMon = 0x005E2414, kLuckyDay = 0x005E247C;
    constexpr DWORD kLuckyHF = 0x005E24E4, kLuckyHT = 0x005E26DC, kLuckyVal = 0x005E2744;

    // сверка: код стока, который пишет / читает эти адреса (снят с GameServer.exe e7b4ac38)
    const BYTE kRdExpCnt[7] = { 0x0F, 0xBF, 0x05, 0x64, 0x79, 0x5A, 0x00 };   // 0x4CC410 GetExpUpDownValue: movsx eax,[0x5A7964]
    const BYTE kRdExpVal[5] = { 0xA1, 0x44, 0x27, 0x5E, 0x00 };               // 0x4CC487 mov eax,[0x5E2744]
    const BYTE kSendOrig[3] = { 0x55, 0x8B, 0xEC };                           // sub_4C28F0 пролог

    typedef int (__fastcall *PFN_ToClient)(void* tr, void* edx, int op, int len, int userNum, const void* buf, int a6, int a7); // sub_4C28F0
    PFN_ToClient const pToClient = (PFN_ToClient)Srv::kSendPacket;

    struct SlotSt
    {
        bool  seen;          // слот уже видели в мире
        bool  inworld;
        bool  fresh;         // ★ ревизия 49 С-1: новый вход — что у клиента, НЕИЗВЕСТНО (портал Astory = новое соединение, а клиент
                             //   прежней версии значок не сбрасывает): первый такт шлёт явное состояние обоих видов
        LONG  gen;           // ★ ревизия 49 Н-3: поколение соединения слота на момент снимка
        int   uid, idx, map;
        bool  dropOn;  float dropMult;     // что послано (клиент)
        bool  expOn;   float expMult;      // опыт: true — значок горит по нашему 6039 (событие или «1 + час»)
    };
    SlotSt g_st[kSlots] = {};
    volatile LONG g_gen[kSlots] = {};      // ★ ревизия 49 Н-3: +1 на каждый разрыв / новое соединение слота (P73_OnConnFlag)
    volatile LONG g_enabled = 0;
    bool  g_expLucky = true;
    volatile LONG g_sent39 = 0, g_sent41 = 0, g_faults = 0;
#ifdef ASDA_PATCH_STAND
    volatile LONG g_testKey = 0;           // стенд: подменные часы ММДДччмм (0 — настоящие)
#endif
    volatile LONG g_nowKey = 0; volatile LONG g_nowTick = 0; volatile LONG g_nowLuckyRow = -1; volatile LONG g_nowLuckyV = 0;

    // ММДДччмм и строка счастливого часа — раз в секунду на процесс
    void Clock(int* key, int* luckyRow, float* luckyVal)
    {
        const DWORD t = GetTickCount();
        if (!g_nowTick || (DWORD)(t - (DWORD)g_nowTick) >= 1000u)
        {
            SYSTEMTIME s; GetLocalTime(&s);
            int k = s.wMinute + 100 * s.wHour + 10000 * s.wDay + 1000000 * s.wMonth;
#ifdef ASDA_PATCH_STAND
            if (g_testKey) { k = g_testKey; }          // ★ ревизия 49 М-5: стенд не зависит от реальных часов (31.12 23:59)
#endif
            int row = -1; float v = 0.0f;
            __try
            {
                const int n = *(volatile short*)kLuckyCnt;
                const short* y = *(short* const*)kLuckyYear; const char* m = *(char* const*)kLuckyMon; const char* d = *(char* const*)kLuckyDay;
                const char* hf = *(char* const*)kLuckyHF; const char* ht = *(char* const*)kLuckyHT; const float* vv = *(float* const*)kLuckyVal;
                if (y && m && d && hf && ht && vv)
                {
                    for (int i = 0; i < n; ++i)
                    {
                        if (y[i] == (short)s.wYear && m[i] == (char)s.wMonth && d[i] == (char)s.wDay && hf[i] <= (int)s.wHour && ht[i] > (int)s.wHour)
                        {
                            row = i; v = vv[i]; break;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { row = -1; v = 0.0f; }
            InterlockedExchange(&g_nowKey, k);
            InterlockedExchange(&g_nowLuckyRow, row);
            InterlockedExchange(&g_nowLuckyV, *(LONG*)&v);
            InterlockedExchange(&g_nowTick, (LONG)(t ? t : 1));
        }
        *key = g_nowKey; *luckyRow = g_nowLuckyRow; const LONG lv = g_nowLuckyV; *luckyVal = *(const float*)&lv;
    }

    // Событие типа t на карте m идёт сейчас? value — множитель зеркала.
    bool Active(int t, int m, int key, float* value)
    {
        const int i = kMaps * t + m;
        const int s = ((const int*)kSTime)[i], e = ((const int*)kETime)[i];
        *value = ((const float*)kValue)[i];
        return s <= key && key < e && !(s == 0 && e == 0);
    }

    void Send6039(void* th, int num, int t, int m, float mult)
    {
        BYTE b[30] = {};                       // тело ответа NpcServer → оператору (recvOperatorCommandEventSet копирует 30 б с +9)
        const int i = kMaps * t + m;
        b[0] = 1;                              // успех
        *(short*)(b + 5) = (short)num;         // userNum получателя (сток кладёт сюда оператора)
        b[7] = ((const BYTE*)kSMon)[i]; b[8] = ((const BYTE*)kSDay)[i]; b[9] = ((const BYTE*)kSHour)[i]; b[10] = ((const BYTE*)kSMin)[i];
        b[11] = ((const BYTE*)kEMon)[i]; b[12] = ((const BYTE*)kEDay)[i]; b[13] = ((const BYTE*)kEHour)[i]; b[14] = ((const BYTE*)kEMin)[i];
        b[15] = (BYTE)t;
        memcpy(b + 16, &mult, 4);
        *(int*)(b + 20) = -1;                  // канал
        *(int*)(b + 24) = m;                   // карта
        b[28] = ((const BYTE*)kMinLv)[i]; b[29] = ((const BYTE*)kMaxLv)[i];
        pToClient(th, nullptr, 6039, 30, num, b, num, 1);
        InterlockedIncrement(&g_sent39);
    }

    void Send6041(void* th, int num, int t, int m)
    {
        BYTE b[16] = {};                       // тело 6041 (recvOperatorCommandEventOff — 16 б)
        b[0] = 1;
        *(short*)(b + 5) = (short)num;
        b[7] = (BYTE)t;
        *(int*)(b + 8) = -1;
        *(int*)(b + 12) = m;
        pToClient(th, nullptr, 6041, 16, num, b, num, 1);
        InterlockedIncrement(&g_sent41);
    }

    bool Diff(float a, float b) { return a - b > 0.001f || b - a > 0.001f; }
}

// Нить карты: такт игрока (P73_OnCheckUser). Только чтение зеркала и отправка своему игроку.
extern "C" void __stdcall P128_OnUserTick(void* mgr, int userNum, BYTE* user)
{
    if (!g_enabled) { return; }
    userNum = (short)userNum;
    if (userNum < 0 || userNum >= kSlots || !user || !mgr) { return; }
    SlotSt& st = g_st[userNum];
    __try
    {
        const bool inworld = *(const int*)(user + kOffInWorld) == 1;
        if (!inworld) { st.inworld = false; return; }
        const int uid = *(const int*)(user + kOffUserIdx), idx = user[kOffCharSlot];
        BYTE* th = *(BYTE**)((BYTE*)mgr + kOffThread);
        if (!th) { return; }
        const int map = *(const int*)(th + kOffMapIdx);
        const LONG gen = g_gen[userNum];
        if (!st.seen || !st.inworld || st.uid != uid || st.idx != idx || st.gen != gen)
        {
            // новый вход в мир (или возврат в мир, или новое соединение слота): что горит у клиента — неизвестно
            st.seen = true; st.uid = uid; st.idx = idx; st.map = map; st.gen = gen; st.fresh = true;
            st.dropOn = false; st.dropMult = 1.0f; st.expOn = false; st.expMult = 1.0f;
        }
        st.inworld = true; st.map = map;
        if (map < 0 || map >= kMaps) { return; }
        int key = 0, lrow = -1; float lval = 0.0f;
        Clock(&key, &lrow, &lval);
        float v0 = 0.0f, v1 = 0.0f;
        const bool on0 = Active(0, map, key, &v0);
        const bool on1 = Active(1, map, key, &v1);
        const float lucky = g_expLucky && lrow >= 0 ? lval : 0.0f;
        if (st.fresh)
        {
            // ★ ревизия 49 С-1: первый такт нового входа — явное состояние обоих видов (погасить то, что могло остаться с прошлой карты)
            st.fresh = false;
            if (on0) { Send6039(th, userNum, 0, map, v0); st.dropOn = true; st.dropMult = v0; }
            else     { Send6041(th, userNum, 0, map); }           // 4301 вид 2/3 сток не ставит — значок часа не задевается
            if (on1)               { Send6039(th, userNum, 1, map, v1 + lucky); st.expOn = true; st.expMult = v1 + lucky; }
            else if (lrow >= 0 && lval > 0.0f)                     // идёт час (при любом ExpWithLuckyHours: 6041 погасил бы значок 4301)
            { Send6039(th, userNum, 1, map, 1.0f + lval); st.expOn = true; st.expMult = 1.0f + lval; }
            else                   { Send6041(th, userNum, 1, map); }
            return;
        }
        // тип 0 — добыча и золото
        if (on0 && (!st.dropOn || Diff(st.dropMult, v0))) { Send6039(th, userNum, 0, map, v0); st.dropOn = true; st.dropMult = v0; }
        else if (!on0 && st.dropOn) { Send6041(th, userNum, 0, map); st.dropOn = false; st.dropMult = 1.0f; }
        // тип 1 — опыт (+ счастливый час)
        if (on1)
        {
            const float want = v1 + lucky;
            if (!st.expOn || Diff(st.expMult, want)) { Send6039(th, userNum, 1, map, want); st.expOn = true; st.expMult = want; }
        }
        else if (st.expOn)
        {
            if (lucky > 0.0f)
            {
                const float want = 1.0f + lucky;   // событие кончилось, счастливый час идёт — значок часа (как 4301)
                if (Diff(st.expMult, want)) { Send6039(th, userNum, 1, map, want); st.expMult = want; }
            }
            else { Send6041(th, userNum, 1, map); st.expOn = false; st.expMult = 1.0f; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_faults); }
}

// Разрыв / новое соединение слота (P73_OnConnFlag, нить IOCP под замком Ciocp): только сброс таблицы слота.
extern "C" void __stdcall P128_OnConnFlag(int slot, int flag)
{
    (void)flag;
    if (slot < 0 || slot >= kSlots) { return; }
    InterlockedIncrement(&g_gen[slot]);   // ★ ревизия 49 Н-3: такт сравнит поколение со своим снимком (без гонки с seen / inworld)
    g_st[slot].seen = false; g_st[slot].inworld = false;
}

extern "C" __declspec(dllexport) void __stdcall P128_GetStats(LONG* sent6039, LONG* sent6041, LONG* faults)
{
    if (sent6039) { *sent6039 = g_sent39; } if (sent6041) { *sent6041 = g_sent41; } if (faults) { *faults = g_faults; }
}

bool P128_Applied() { return g_enabled != 0; }

#ifdef ASDA_PATCH_STAND
// Стенд: сбросить кэш часов (после смены зеркала/таблицы часов стендом) и таблицу слотов.
extern "C" __declspec(dllexport) void __stdcall P128_TestReset() { InterlockedExchange(&g_nowTick, 0); memset(g_st, 0, sizeof(g_st));
                                                                   memset((void*)g_gen, 0, sizeof(g_gen)); }
extern "C" __declspec(dllexport) void __stdcall P128_TestBumpGen(int slot) { if (slot >= 0 && slot < kSlots) { InterlockedIncrement(&g_gen[slot]); } }
extern "C" __declspec(dllexport) void __stdcall P128_TestSetKey(int key) { InterlockedExchange(&g_testKey, key); InterlockedExchange(&g_nowTick, 0); }
extern "C" __declspec(dllexport) void __stdcall P128_TestClock() { InterlockedExchange(&g_nowTick, 0); }
extern "C" __declspec(dllexport) void __stdcall P128_TestTick(void* mgr, int num, BYTE* user) { P128_OnUserTick(mgr, num, user); }
#endif

PatchResult P128_EventBadgeAll()
{
    InterlockedExchange(&g_enabled, 0);
    if (!Config::GetBool(kSec, L"Enabled", true)) { return PatchResult::Disabled; }
    g_expLucky = Config::GetBool(kSec, L"ExpWithLuckyHours", true);
    const Site sites[] =
    {
        { 0x004CC410, kRdExpCnt, sizeof(kRdExpCnt) },
        { 0x004CC487, kRdExpVal, sizeof(kRdExpVal) },
    };
    if (!VerifyAllSites(L"P128", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    // sub_4C28F0 только ВЫЗЫВАЕТСЯ: годится стоковый пролог или jmp rel32 (врезка патча, стоящего раньше, — как FuncStartOk P127)
    if (!Hook::Verify(Srv::kSendPacket, kSendOrig, 3) && *(const BYTE*)Srv::kSendPacket != 0xE9)
    {
        wchar_t hex[40]; Hook::Dump(Srv::kSendPacket, 6, hex, ARRAYSIZE(hex));
        Log::Line(L"    MISMATCH P128 @0x%08X (sub_4C28F0): ожидалось [55 8b ec] или jmp, в памяти [%s]", Srv::kSendPacket, hex);
        return PatchResult::Mismatch;
    }
    memset(g_st, 0, sizeof(g_st));
    InterlockedExchange(&g_enabled, 1);
    if (!P73_UserTickInstall())
    {
        InterlockedExchange(&g_enabled, 0);
        Log::Line(L"    P128: [ОШИБКА] общая точка UserTick 0x526CEB не поставлена (байты не совпали) — значок не рассылается");
        return PatchResult::Mismatch;
    }
    if (!P73_EventsHooked())
    {
        Log::Line(L"    P128: события разрыва не доходят до P73_OnConnFlag — новый вход узнаётся по выходу из мира и смене персонажа слота");
    }
    Log::Line(L"    P128: значок события Event.dat всем игрокам — такт игрока (UserTick 0x526CEB): 6039 / 6041 при изменении (вход в мир, "
              L"смена карты, команда, начало/конец окна); опыт + счастливый час %s", g_expLucky ? L"да" : L"нет");
    return PatchResult::Applied;
}
