// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P68 — ★ ИМЯ ПЕРСОНАЖА: серверная проверка при смене имени 6138/6140 + дефект стока «имя в памяти меняется
//  при отказе БД» (античит, волна A13, 2026-10-13). [СЕРВЕР-ДОРАБОТКА] Протокол не меняется.
//
//  ── ДЫРА ──
//  6138 RecvClient_CharNameCheck@0x55D7C0 (GameServer.c:134655) — после стоковых проверок (анти-повтор sub_524390,
//  подпись sub_523F00 0x18, GetUser, charId) имя 20 б тела уходит в БД 2450 (DBManager sub_439C80 → `EXEC UPNickCheck '%s'`)
//  без единой проверки. 6140 RecvClient_CharNameChange@0x55D910 (GameServer.c:134697) — после проверок предмета
//  (слот, тип +27 == 111) имя уходит в БД 2452 (sub_439E80 → `EXEC UPCharRename …, '%s', …`). Правила имени есть только
//  у клиента — модифицированный клиент ставит любое имя: управляющие байты, пробел/знаки, 20 б без нуля (тогда '%s'
//  DBManager читает за поле, а CUser+0x178 остаётся без терминатора), а 6140 без 6138 обходит проверку занятости
//  и LewdWordList (их делает ТОЛЬКО UPNickCheck; UPCharRename их не повторяет).
//
//  ── ПРАВИЛА ОРИГИНАЛЬНОГО КЛИЕНТА (эталон AsdaStory.exe 13 344 768 б) ──
//   • смена имени (окно CharNameChange_Win, кнопка 7905, ui_core.c:47740 / AsdaStory_game.c:348366): поле 7904 LimitText=20
//     (gamemain_jui.ini), `uiEditGetWindowTextWithSuffix(…, 0x14)` → GetWindowTextA(…,20) → ≤ 19 б; равное текущему → 101118;
//     `Chat_MatchBannedWord(…, 1)@0xBB2830`: режим 1 = `validateStringByLocale@0x956090` (символы по локали сборки) +
//     слова CurseTable.bin → 7009; иначе 6138. Тот же буфер (g_nItemUpgradeLevel = self+4373) уходит в 6140 после
//     подтверждения 109405 (ветки 0x42/0x43, AsdaStory_game.c:380150–380167).
//   • создание (CaraMake, AsdaStory_game.c:534790): поле LimitText 18 (0x534255), `validateStringByLocale` + запрет «'» → 9583.
//   • локаль: case 2/6 `isValidNameCharAscii@0x9570A0` = A-Z a-z 0-9 (так собран русский эталон порта); case 7
//     `isValidNameCharCyrillic@0x957250` = + байты cp1251 ≥ 0xC0, 0xA8, 0xB8; case 8 `isDelimiterChar@0x957610` (мисней, арабская
//     локаль) = + байты cp1256 ≥ 0xC0 кроме 0xD7.
//  Серверная проверка — ТОЛЬКО эти правила + очевидно безопасные (нет нуля в 20 б, управляющие байты):
//   правило 1 — пусто; 2 — нет нуля в поле 20 б (длина > 19); 3 — байт 0x01..0x1F или 0x7F; 4 — символ вне правил:
//     NameCharset=0 (умолчание): A-Z a-z 0-9 (эталон и решение владельца 08.10 «имена — только латиница», порт
//       asda.Text.NameLocale 0);
//     NameCharset=1: объединение локалей 7/8 оригинала в том виде, как их шлёт порт при asda.Text.NameLocale 1:
//       (А) каждый байт A-Z a-z 0-9 / ≥ 0xC0 / 0xA8 / 0xB8 (cp1251 и cp1256 оригинала);
//       (Б) маркер порта 0x98 + байты по (А) (арабское имя, кодек провода порта, FAsdaLoginData::EncodeWireText);
//       (В) строгий UTF-8 из A-Z a-z 0-9, кириллицы U+0410..U+044F/U+0401/U+0451 и букв cp1256 ≥ 0xC0 кроме 0xD7
//           (ветка UTF-8 кодека порта: «РЁ…» и т. п.).
//   Слова CurseTable.bin, LewdWordList и занятость — в SQL (A13), где лежат данные.
//  Проверки GM-префикса в оригинале НЕТ (ни строки в клиенте, ни в LoginManager/GameServer/DBManager) — не добавляется.
//
//  ── ДЕФЕКТ СТОКА (KeepNameOnDbFail) ──
//  sub_55DD50 (ответ БД 2453, GameServer.c:134821) копирует новое имя в CUser+0x178 (0x55DFDF `call memcpy`) ПРИ ЛЮБОМ
//  флаге БД: 0 (ошибка/отказ A13), 2/3 (в клане), 4 (предмет на аукционе) — в БД имя не сменилось, предмет не снят, а в
//  памяти сервера до перезахода — новое имя (видят все, его пишет журнал/чат). Честный член клана, нажавший «сменить»,
//  получает 109406 и чужое имя в памяти. Правка: копировать только при флаге 1 (как сток снимает предмет — 0x55DECB).
//
//  ── ПЛОЩАДКИ (E8 rel32 `call memcpy 0x56A040`, cdecl; байты одинаковы в стоке 4e20f0ad и живых GameServer/Indun e7b4ac38) ──
//   A. 0x55D8CE (6138, копия имени в тело БД 2450 — ПОСЛЕ всех стоковых проверок). Кадр: this=[ebp-4Ch], CUser*=[ebp-44h],
//      userNum=[ebp+8], тело=[ebp-40h] (+0 charId, +4 имя 20 б). Отказ (Mode=1): 6139 {charId, флаг 3} — как сток отвечает
//      на «LewdWord» UPNickCheck (клиент: 109404 «Имя уже кем-то занято»), 2450 не уходит → эпилог 0x55D8FC.
//   B. 0x55DC6C (6140, копия имени в тело БД 2452 — после проверок предмета/клана/отряда). Кадр: this=[ebp-0ECh],
//      CUser*=[ebp-0E4h], тело=[ebp-0E0h] (+4 имя), ответ 6141 = [ebp-80h], код = [ebp-68h]. Отказ: код 0 (тот же, что
//      шлёт сток при отказе БД; клиент: 109411) → СТОКОВЫЙ хвост 0x55DAA2 (push 1/-1/тело/userNum/56h/17FDh; sub_4C28F0;
//      jmp эпилог 0x55DC9D).
//   C. 0x55DFDF (2453, memcpy имени в CUser+0x178). Кадр: флаг БД = byte [ebp-9Dh] (сток сам сравнивает его с 1 в 0x55DECB).
//      Пропуск копии = `ret` (cdecl, вызывающий снимает 12 б; eax дальше не читается — 0x55DFEB `lea eax,…`).
//   Соседи P63 (0x55D923 вход 6140, 0x55DC98 отправка 2452, 0x43332A вызов sub_55DD50) не пересекаются.
//  Журнал ac.other: вид 53 — имя нарушает правило (6138/6140), v[0]=правило, v[1]=длина, v[2]=(позиция<<8)|байт;
//  вид 54 — 6140 с именем, не совпадающим с последним 6138 этой сессии (обход UPNickCheck), v[0]=было ли 6138;
//  вид 55 — пишет SQL (A13), не DLL. Ограничитель: 1 строка на (сессия, вид) за JournalIntervalSec.
//
//  ── ИСКЛЮЧЕНИЕ ДЛЯ ОПЕРАТОРОВ (OperatorExempt, решение владельца 13.10.2026, интеграция integ3) ──
//  Если отправитель 6138/6140 — оператор, правило имени (вид 53) и сверка с последним 6138 (вид 54) к нему НЕ применяются:
//  ни журнала, ни отказа, сток как есть. Признак — тот же, что у гейта операторских опкодов P47: GM-флаг CUser+0x40B9F == 1
//  через sub_52ED50(this обработчика, userNum) — общая точка P47_IsGmUser (Patches.h), поле здесь не читается. Флаг ставит
//  только DBManager: при загрузке персонажа EXEC UPCharGMInfo <UserIndex> (= 1, если в Joy1.dbo.CharGmInfo есть строка
//  Userindex с GMFlag не NULL) → DB 2801 {UserIndex, флаг} → sub_560160 (сверка с CUser+0x174) → CUser+0x40B9F.
//  Исправление дефекта стока на 2453 (KeepNameOnDbFail) от исключения НЕ зависит — для всех.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include <stdio.h>
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"
#include <string.h>

namespace
{
    const wchar_t* kSec = L"P68_CharNameGuard";

    bool g_enabled           = true;
    int  g_mode              = 0;     // 0 журнал, 1 отказ
    int  g_charset           = 0;     // 0 A-Z a-z 0-9; 1 объединение локалей 7/8 + кодеки порта
    bool g_check6138         = true;
    bool g_check6140         = true;
    bool g_require6138       = true;  // 6140 только с именем последнего 6138 этой сессии (вид 54)
    bool g_keepNameOnDbFail  = true;  // C: копировать имя в CUser только при флаге БД 1
    bool g_operatorExempt    = true;  // ★ integ3: оператор (GM-флаг, как у P47) — без правила имени и сверки 6138→6140
    int  g_journalIntervalSec = 10;

    typedef int  (__thiscall *FnSendPacket)(void* net, short op, short len, short idx, void* body, short a6, int a7);   // 0x4C28F0
    typedef void (__cdecl    *PFN_SrvLog)(int cat, const char* fmt, ...);                                           // 0x569DF0
    const FnSendPacket SrvSendPacket = (FnSendPacket)Srv::kSendPacket;
    PFN_SrvLog   const pSrvLog       = (PFN_SrvLog)Srv::kLog;

    constexpr int kOffUserIndex = 0x174;   // CUser: charId (сток сверяет его с телом +0 и с ответом БД)
    constexpr int kOffName      = 0x178;   // CUser: имя 20 б
    constexpr int kOffSlot      = 0x18C;
    constexpr int kNameField    = 20;

    enum Kind : BYTE { kNameRule = 53, kNameNotChecked = 54 };   // 55 — SQL A13 (пишет база, не DLL)

    struct Sess
    {
        int   userIndex;
        int   charSlot;     // ★ fix2 (НИЗК-8 integ3): ключ записи — (CUser+0x174, CUser+0x18C): смена персонажа сбрасывает «последний 6138»
        bool  haveLast;
        BYTE  lastName[kNameField];
        DWORD lastJournal[2];
        int   suppressed[2];
    };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    volatile LONG g_exempt = 0;       // ★ integ3: 6138/6140 операторов, пропущенных без проверки
    volatile LONG g_checked6138 = 0, g_checked6140 = 0, g_viol = 0, g_notChecked = 0, g_refused = 0, g_kept = 0, g_db2453 = 0;

    bool SessOk(int userNum) { return userNum >= 0 && userNum < 0x226; }

    // ★ fix2 (НИЗК-10 integ3): поля CUser читаются ДО захвата g_lock (KeyOf, под __try вызывающего) — исключение при
    //   чтении чужой памяти больше не может случиться под замком и запереть его навсегда.
    struct SessKey { int userIndex; int charSlot; };
    SessKey KeyOf(const BYTE* user)
    {
        SessKey k{ 0, -1 };
        if (user) { k.userIndex = *(const int*)(user + kOffUserIndex); k.charSlot = user[kOffSlot]; }
        return k;
    }
    Sess& SessOf(int userNum, const SessKey& k)
    {
        Sess& s = g_sess[userNum];
        if (s.userIndex != k.userIndex || s.charSlot != k.charSlot)
        {
            memset(&s, 0, sizeof(s)); s.userIndex = k.userIndex; s.charSlot = k.charSlot;
        }
        return s;
    }

    bool Allow(Sess& s, int kindIdx, DWORD now)
    {
        if (g_journalIntervalSec <= 0) { return true; }
        if (s.lastJournal[kindIdx] && now - s.lastJournal[kindIdx] < (DWORD)g_journalIntervalSec * 1000) { ++s.suppressed[kindIdx]; return false; }
        s.lastJournal[kindIdx] = now;
        return true;
    }

    void Journal(BYTE kind, const BYTE* user, int userNum, int opcode, int v0, int v1, int v2, const char* text, int suppressed)
    {
        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)userNum;
        e.ip = P47_PeerIpv4(userNum);
        e.suppressed = suppressed;
        if (user)
        {
            __try
            {
                e.userIndex = *(const int*)(user + kOffUserIndex);
                e.charSlot  = user[kOffSlot];
                AcJournal::CopyName(e, user + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = v0; e.v[1] = v1; e.v[2] = v2;
        AcJournal::CopyText(e, text);
        AcJournal::Push(e);
    }

    const char* NameOf(const BYTE* user) { return user ? (const char*)(user + kOffName) : "?"; }

    // ── правило символов ──
    bool IsAlnum(BYTE c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
    bool IsLocaleByte(BYTE c) { return IsAlnum(c) || c >= 0xC0 || c == 0xA8 || c == 0xB8; }   // case 7 ∪ case 8 оригинала

    // Буквы cp1256 с байтом ≥ 0xC0 кроме 0xD7 (арабская локаль оригинала) — кодпойнты (таблица = GAsdaCp1256Hi порта
    // [0x40..0x7F] = стандартная cp1256).
    const WORD kCp1256Hi[64] =
    {
        0x06C1, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, 0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F,
        0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x00D7, 0x0637, 0x0638, 0x0639, 0x063A, 0x0640, 0x0641, 0x0642, 0x0643,
        0x00E0, 0x0644, 0x00E2, 0x0645, 0x0646, 0x0647, 0x0648, 0x00E7, 0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0649, 0x064A, 0x00EE, 0x00EF,
        0x064B, 0x064C, 0x064D, 0x064E, 0x00F4, 0x064F, 0x0650, 0x00F7, 0x0651, 0x00F9, 0x0652, 0x00FB, 0x00FC, 0x200E, 0x200F, 0x06D2,
    };

    bool IsNameCodepoint(unsigned cp)
    {
        if (cp < 0x80) { return IsAlnum((BYTE)cp); }
        if (cp == 0x0401 || cp == 0x0451 || (cp >= 0x0410 && cp <= 0x044F)) { return true; }
        for (int i = 0; i < 64; ++i) { if (i != 0x17 && kCp1256Hi[i] == cp) { return true; } }
        return false;
    }

    // Строгий UTF-8 (2 и 3 байта, без избыточных форм и суррогатов), все кодпойнты — буквы имени.
    bool IsUtf8Name(const BYTE* p, int len)
    {
        for (int i = 0; i < len; )
        {
            const BYTE b = p[i];
            unsigned cp = 0; int n = 0;
            if (b < 0x80) { cp = b; n = 1; }
            else if (b >= 0xC2 && b <= 0xDF) { if (i + 1 >= len || (p[i + 1] & 0xC0) != 0x80) { return false; } cp = ((b & 0x1Fu) << 6) | (p[i + 1] & 0x3Fu); n = 2; }
            else if (b >= 0xE0 && b <= 0xEF)
            {
                if (i + 2 >= len || (p[i + 1] & 0xC0) != 0x80 || (p[i + 2] & 0xC0) != 0x80) { return false; }
                cp = ((b & 0x0Fu) << 12) | ((p[i + 1] & 0x3Fu) << 6) | (p[i + 2] & 0x3Fu); n = 3;
                if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) { return false; }
            }
            else { return false; }
            if (!IsNameCodepoint(cp)) { return false; }
            i += n;
        }
        return true;
    }
}

// Вердикт по полю имени 20 б: 0 — допустимо; 1 пусто; 2 нет нуля (длина > 19); 3 управляющий байт; 4 символ вне правил.
// *len — длина до нуля (20 = нуля нет), *pos/*bad — первая позиция/байт нарушения (−1 — нет).
// Экспорт для стенда (tools/stand_p68) — та же функция, что у площадок.
extern "C" __declspec(dllexport) int __stdcall P68_NameVerdict(const BYTE* f, int charset, int* len, int* pos, int* bad)
{
    int n = 0;
    while (n < kNameField && f[n]) { ++n; }
    if (len) { *len = n; } if (pos) { *pos = -1; } if (bad) { *bad = -1; }
    if (n == kNameField) { return 2; }
    if (n == 0) { return 1; }
    for (int i = 0; i < n; ++i)
    {
        if (f[i] < 0x20 || f[i] == 0x7F) { if (pos) { *pos = i; } if (bad) { *bad = f[i]; } return 3; }
    }
    int first = -1;
    if (charset == 0)
    {
        for (int i = 0; i < n; ++i) { if (!IsAlnum(f[i])) { first = i; break; } }
        if (first < 0) { return 0; }
    }
    else
    {
        bool allLocale = true;
        for (int i = 0; i < n; ++i) { if (!IsLocaleByte(f[i])) { allLocale = false; break; } }
        if (allLocale) { return 0; }                                                   // (А)
        if (f[0] == 0x98 && n >= 2)
        {
            bool rest = true;
            for (int i = 1; i < n; ++i) { if (!IsLocaleByte(f[i])) { rest = false; break; } }
            if (rest) { return 0; }                                                    // (Б)
        }
        if (IsUtf8Name(f, n)) { return 0; }                                            // (В)
        for (int i = (f[0] == 0x98 ? 1 : 0); i < n; ++i) { if (!IsLocaleByte(f[i])) { first = i; break; } }
        if (first < 0) { first = 0; }
    }
    if (pos) { *pos = first; } if (bad) { *bad = f[first]; }
    return 4;
}

namespace
{
    // Деталь для журнала (≤ 63 б): "6140 r4 L7 p3 x5F n=GM_Rimy", непечатаемые байты — \xNN.
    void Detail(char* out, size_t cap, int opcode, int rule, int len, int pos, int bad, const BYTE* f)
    {
        int k = _snprintf_s(out, cap, _TRUNCATE, "%d r%d L%d p%d x%02X n=", opcode, rule, len, pos, bad < 0 ? 0 : bad);
        if (k < 0) { return; }
        size_t o = (size_t)k;
        const int n = len > kNameField ? kNameField : len;
        for (int i = 0; i < n && o + 5 < cap; ++i)
        {
            const BYTE c = f[i];
            if (c >= 0x21 && c <= 0x7E && c != '\\') { out[o++] = (char)c; }
            else { o += (size_t)_snprintf_s(out + o, cap - o, _TRUNCATE, "\\x%02X", c); }
        }
        out[o < cap ? o : cap - 1] = 0;
    }

    // Нарушение правила: журнал (с ограничителем) + строка Log_Item. Возврат: 1 — отказать (Mode=1).
    int OnRule(int opcode, const BYTE* user, int userNum, const BYTE* f, int rule, int len, int pos, int bad, const char* refuseText)
    {
        InterlockedIncrement(&g_viol);
        char text[64]; Detail(text, sizeof(text), opcode, rule, len, pos, bad, f);
        const SessKey key = KeyOf(user);                        // ★ fix2: чтение CUser — до замка
        EnterCriticalSection(&g_lock);
        Sess& s = SessOf(userNum, key);
        const bool allow = Allow(s, 0, GetTickCount());
        const int sup = s.suppressed[0];
        if (allow) { s.suppressed[0] = 0; }
        LeaveCriticalSection(&g_lock);
        if (allow)
        {
            pSrvLog(1, "P68 CharNameGuard: %s, %s UserNum %d%s", text, NameOf(user), userNum, g_mode ? refuseText : " (journal, Mode=0)");
            Journal(kNameRule, user, userNum, opcode, rule, len, ((pos & 0xFFFF) << 8) | (bad & 0xFF), text, sup);
        }
        return g_mode == 1 ? 1 : 0;
    }
}

// ── A. 6138: после всех стоковых проверок, перед копией имени в тело DB-2450. Возврат 1 → 6139 «занято» отправлен, эпилог ──
extern "C" int __stdcall P68_OnName6138(BYTE* ebp)
{
    if (!g_enabled || !g_check6138) { return 0; }
    int verdict = 0;
    __try
    {
        const int   userNum = *(const short*)(ebp + 8);
        BYTE*       self    = *(BYTE* const*)(ebp - 0x4C);
        const BYTE* user    = *(const BYTE* const*)(ebp - 0x44);
        const BYTE* name    = ebp - 0x3C;                       // тело [ebp-40h] +4
        // ★ integ3: оператор (GM-флаг, общая точка P47) — без правила и без запоминания имени, сток как есть.
        if (g_operatorExempt && P47_IsGmUser(self, userNum)) { InterlockedIncrement(&g_exempt); return 0; }
        InterlockedIncrement(&g_checked6138);
        if (!SessOk(userNum)) { return 0; }
        const SessKey key = KeyOf(user);                        // ★ fix2: чтение CUser — до замка
        EnterCriticalSection(&g_lock);
        Sess& s = SessOf(userNum, key);
        memcpy(s.lastName, name, kNameField);                  // запоминаем имя 6138 в любом случае (честный клиент шлёт этот же буфер в 6140)
        s.haveLast = true;
        LeaveCriticalSection(&g_lock);
        int len = 0, pos = -1, bad = -1;
        const int rule = P68_NameVerdict(name, g_charset, &len, &pos, &bad);
        if (rule && OnRule(6138, user, userNum, name, rule, len, pos, bad, " -> REFUSE 6139 flag 3"))
        {
            BYTE body[5] = {};
            *(int*)body = user ? *(const int*)(user + kOffUserIndex) : *(const int*)(ebp - 0x40);
            body[4] = 3;                                        // как UPNickCheck «LewdWord» → клиент 109404
            void* net = self ? *(void**)(self + 4) : nullptr;
            if (net) { SrvSendPacket(net, (short)6139, 5, (short)userNum, body, -1, 1); }
            InterlockedIncrement(&g_refused);
            verdict = 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── B. 6140: после всех стоковых проверок, перед копией имени в тело DB-2452. Возврат 1 → 6141 код 0 стоковым хвостом ──
extern "C" int __stdcall P68_OnName6140(BYTE* ebp)
{
    if (!g_enabled || !g_check6140) { return 0; }
    int verdict = 0;
    __try
    {
        const int   userNum = *(const short*)(ebp + 8);
        BYTE*       self    = *(BYTE* const*)(ebp - 0xEC);       // this обработчика (0x55D9AD mov ecx,[ebp-0ECh])
        const BYTE* user    = *(const BYTE* const*)(ebp - 0xE4);
        const BYTE* name    = ebp - 0xDC;                       // тело [ebp-0E0h] +4
        // ★ integ3: оператор (GM-флаг, общая точка P47) — ни вида 53, ни вида 54, сток как есть.
        if (g_operatorExempt && P47_IsGmUser(self, userNum)) { InterlockedIncrement(&g_exempt); return 0; }
        InterlockedIncrement(&g_checked6140);
        if (!SessOk(userNum)) { return 0; }
        int len = 0, pos = -1, bad = -1;
        const int rule = P68_NameVerdict(name, g_charset, &len, &pos, &bad);
        if (rule)
        {
            verdict = OnRule(6140, user, userNum, name, rule, len, pos, bad, " -> REFUSE 6141 code 0");
        }
        else if (g_require6138)
        {
            const SessKey key = KeyOf(user);                    // ★ fix2: чтение CUser — до замка
            EnterCriticalSection(&g_lock);
            Sess& s = SessOf(userNum, key);
            const bool had  = s.haveLast;
            const bool same = had && strncmp((const char*)s.lastName, (const char*)name, kNameField) == 0;
            int sup = 0; bool allow = false;
            if (!same)
            {
                allow = Allow(s, 1, GetTickCount());
                sup = s.suppressed[1];
                if (allow) { s.suppressed[1] = 0; }
            }
            LeaveCriticalSection(&g_lock);
            if (!same)
            {
                InterlockedIncrement(&g_notChecked);
                char text[64]; Detail(text, sizeof(text), 6140, had ? 5 : 6, len, -1, -1, name);
                if (allow)
                {
                    pSrvLog(1, "P68 CharNameGuard: 6140 name != last 6138 (%s) %s, %s UserNum %d%s", had ? "other name" : "no 6138",
                            text, NameOf(user), userNum, g_mode ? " -> REFUSE 6141 code 0" : " (journal, Mode=0)");
                    Journal(kNameNotChecked, user, userNum, 6140, had ? 1 : 0, len, 0, text, sup);
                }
                if (g_mode == 1) { verdict = 1; }
            }
        }
        if (verdict) { InterlockedIncrement(&g_refused); }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { verdict = 0; }
    return verdict;
}

// ── C. 2453 (ответ БД на смену имени): 1 → НЕ копировать новое имя в CUser+0x178 (флаг БД != 1) ──
extern "C" int __stdcall P68_OnName2453(BYTE* ebp)
{
    if (!g_enabled || !g_keepNameOnDbFail) { return 0; }
    int skip = 0;
    __try
    {
        InterlockedIncrement(&g_db2453);
        // ★ fix2 (НИЗК-8 integ3): ответ БД на смену имени закрывает пару 6138→6140 — «последний 6138» слота забывается
        //   (следующая смена имени снова требует свежего 6138). userNum читается до замка.
        const int un = *(const short*)(ebp + 8);
        if (SessOk(un)) { EnterCriticalSection(&g_lock); g_sess[un].haveLast = false; LeaveCriticalSection(&g_lock); }
        const int flag = *(const BYTE*)(ebp - 0x9D);
        if (flag != 1)
        {
            InterlockedIncrement(&g_kept);
            const BYTE* user = *(const BYTE* const*)(ebp - 0xC0);
            pSrvLog(1, "P68 CharNameGuard: 2453 flag %d - rename not stored, in-memory name kept (%s, UserNum %d)",
                    flag, NameOf(user), (int)*(const short*)(ebp + 8));
            skip = 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { skip = 0; }
    return skip;
}

extern "C" __declspec(dllexport) void __stdcall P68_GetStats(int* c6138, int* c6140, int* viol, int* notChecked, int* refused, int* kept, int* db2453)
{
    if (c6138) { *c6138 = g_checked6138; } if (c6140) { *c6140 = g_checked6140; } if (viol) { *viol = g_viol; }
    if (notChecked) { *notChecked = g_notChecked; } if (refused) { *refused = g_refused; } if (kept) { *kept = g_kept; }
    if (db2453) { *db2453 = g_db2453; }
}

extern "C" __declspec(dllexport) int __stdcall P68_GetOperatorExempt() { return (int)g_exempt; }

namespace
{
    DWORD g_pMemcpy        = 0x0056A040;   // сток memcpy (cdecl)
    DWORD g_pEpilog6138    = 0x0055D8FC;   // эпилог RecvClient_CharNameCheck
    DWORD g_pRefuseTail6140 = 0x0055DAA2;  // стоковый хвост отказа 6141 (после mov byte [ebp-68h],5)

    // A. вместо `call memcpy` @0x55D8CE (аргументы уже в стеке: dst [ebp-18h], src [ebp-3Ch], 14h). Возврат 0x55D8D3.
    __declspec(naked) void St_Name6138()
    {
        __asm
        {
            pushad
            push  ebp
            call  P68_OnName6138                // __stdcall(ebp) → eax
            mov   dword ptr [esp+28], eax
            popad
            test  eax, eax
            jnz   refuse
            jmp   dword ptr [g_pMemcpy]         // пропуск: сток копирует имя и возвращается на 0x55D8D3
        refuse:
            add   esp, 16                       // адрес возврата + 3 аргумента
            jmp   dword ptr [g_pEpilog6138]     // 6139 уже отправлен из C; 2450 не уходит
        }
    }

    // B. вместо `call memcpy` @0x55DC6C (dst [ebp-23h], src [ebp-0DCh], 14h). Возврат 0x55DC71.
    __declspec(naked) void St_Name6140()
    {
        __asm
        {
            pushad
            push  ebp
            call  P68_OnName6140
            mov   dword ptr [esp+28], eax
            popad
            test  eax, eax
            jnz   refuse
            jmp   dword ptr [g_pMemcpy]
        refuse:
            add   esp, 16
            mov   byte ptr [ebp-68h], 0         // код 6141 = 0 (как отказ БД) → клиент 109411
            jmp   dword ptr [g_pRefuseTail6140] // стоковый хвост: sub_4C28F0(6141, 86 б) → эпилог 0x55DC9D
        }
    }

    // C. вместо `call memcpy` @0x55DFDF (dst CUser+178h, src [ebp-0B8h], 14h). Возврат 0x55DFE4 (add esp,0Ch).
    __declspec(naked) void St_Keep2453()
    {
        __asm
        {
            pushad
            push  ebp
            call  P68_OnName2453
            mov   dword ptr [esp+28], eax
            popad
            test  eax, eax
            jnz   skip
            jmp   dword ptr [g_pMemcpy]
        skip:
            ret                                 // cdecl: аргументы снимет вызывающий
        }
    }

    const BYTE kOrig6138[5] = { 0xE8, 0x6D, 0xC7, 0x00, 0x00 };   // 0x55D8CE call 0x56A040
    const BYTE kOrig6140[5] = { 0xE8, 0xCF, 0xC3, 0x00, 0x00 };   // 0x55DC6C call 0x56A040
    const BYTE kOrig2453[5] = { 0xE8, 0x5C, 0xC0, 0x00, 0x00 };   // 0x55DFDF call 0x56A040
    // Соседи, на которые опираются стабы и C-функции.
    const BYTE kNbArgs6138[10] = { 0x6A, 0x14, 0x8D, 0x55, 0xC4, 0x52, 0x8D, 0x45, 0xE8, 0x50 };             // 0x55D8C4 push 14h; lea edx,[ebp-3Ch]; …
    const BYTE kNbRet6138[3]   = { 0x83, 0xC4, 0x0C };                                                        // 0x55D8D3 add esp,0Ch
    const BYTE kNbEpi6138[16]  = { 0x8B, 0x4D, 0xFC, 0x33, 0xCD, 0xE8, 0x9F, 0xCA, 0x00, 0x00, 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };   // 0x55D8FC
    const BYTE kNbThis6138[3]  = { 0x89, 0x4D, 0xB4 };                                                        // 0x55D7D0 mov [ebp-4Ch],ecx
    const BYTE kNbUser6138[3]  = { 0x89, 0x45, 0xBC };                                                        // 0x55D885 mov [ebp-44h],eax
    const BYTE kNbCmp6138[5]   = { 0x39, 0x45, 0xC0, 0x74, 0x02 };                                            // 0x55D8B7 cmp [ebp-40h],eax; je
    const BYTE kNbArgs6140[13] = { 0x6A, 0x14, 0x8D, 0x95, 0x24, 0xFF, 0xFF, 0xFF, 0x52, 0x8D, 0x45, 0xDD, 0x50 };   // 0x55DC5F
    const BYTE kNbRet6140[3]   = { 0x83, 0xC4, 0x0C };                                                        // 0x55DC71
    const BYTE kNbCode5_6140[4] = { 0xC6, 0x45, 0x98, 0x05 };                                                 // 0x55DA9E mov byte [ebp-68h],5
    const BYTE kNbTail6140[39] = { 0x6A, 0x01, 0x6A, 0xFF, 0x8D, 0x55, 0x80, 0x52, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x6A, 0x56,
                                   0x68, 0xFD, 0x17, 0x00, 0x00, 0x8B, 0x8D, 0x14, 0xFF, 0xFF, 0xFF, 0x8B, 0x49, 0x04,
                                   0xE8, 0x2C, 0x4E, 0xF6, 0xFF, 0xE9, 0xD4, 0x01, 0x00, 0x00 };             // 0x55DAA2 … jmp 0x55DC9D
    const BYTE kNbUser6140[6]  = { 0x89, 0x85, 0x1C, 0xFF, 0xFF, 0xFF };                                      // 0x55DA0D mov [ebp-0E4h],eax
    const BYTE kNbThis6140[6]  = { 0x8B, 0x8D, 0x14, 0xFF, 0xFF, 0xFF };                                      // 0x55D9AD mov ecx,[ebp-0ECh]
    const BYTE kNbArgs2453[22] = { 0x6A, 0x14, 0x8D, 0x8D, 0x48, 0xFF, 0xFF, 0xFF, 0x51, 0x8B, 0x95, 0x40, 0xFF, 0xFF, 0xFF,
                                   0x81, 0xC2, 0x78, 0x01, 0x00, 0x00, 0x52 };                                // 0x55DFC9 … add edx,178h; push edx
    const BYTE kNbRet2453[3]   = { 0x83, 0xC4, 0x0C };                                                        // 0x55DFE4
    const BYTE kNbFlag2453[10] = { 0x0F, 0xB6, 0x95, 0x63, 0xFF, 0xFF, 0xFF, 0x83, 0xFA, 0x01 };             // 0x55DEC4 movzx edx,[ebp-9Dh]; cmp edx,1
    const BYTE kNbMemcpy[5]    = { 0x55, 0x8B, 0xEC, 0x57, 0x56 };                                            // 0x56A040 пролог memcpy
}

PatchResult P68_CharNameGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode              = Config::GetInt(kSec, L"Mode", 0) ? 1 : 0;
    g_charset           = Config::GetInt(kSec, L"NameCharset", 0) ? 1 : 0;
    g_check6138         = Config::GetBool(kSec, L"Check6138", true);
    g_check6140         = Config::GetBool(kSec, L"Check6140", true);
    g_require6138       = Config::GetBool(kSec, L"Require6138Before6140", true);
    g_keepNameOnDbFail  = Config::GetBool(kSec, L"KeepNameOnDbFail", true);
    g_operatorExempt    = Config::GetBool(kSec, L"OperatorExempt", true);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    // ★ fix2 (НИЗК-9 integ3): без проверки 6138 «последнего 6138» не бывает — сверка 6140 с ним считала бы видом 54 КАЖДУЮ
    //   смену имени (а при Mode=1 отклоняла бы все). Check6138=0 выключает Require6138Before6140, о чём строка в PatchLog.
    if (!g_check6138 && g_require6138)
    {
        g_require6138 = false;
        Log::Line(L"    P68: Check6138=0 — Require6138Before6140 выключен (сверять 6140 не с чем)");
    }
    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));

    const Site sitesA[] =
    {
        { 0x0055D8CE, kOrig6138,    sizeof(kOrig6138)    },
        { 0x0055D8C4, kNbArgs6138,  sizeof(kNbArgs6138)  },
        { 0x0055D8D3, kNbRet6138,   sizeof(kNbRet6138)   },
        { 0x0055D8FC, kNbEpi6138,   sizeof(kNbEpi6138)   },
        { 0x0055D7D0, kNbThis6138,  sizeof(kNbThis6138)  },
        { 0x0055D885, kNbUser6138,  sizeof(kNbUser6138)  },
        { 0x0055D8B7, kNbCmp6138,   sizeof(kNbCmp6138)   },
        { 0x0056A040, kNbMemcpy,    sizeof(kNbMemcpy)    },
    };
    const Site sitesB[] =
    {
        { 0x0055DC6C, kOrig6140,    sizeof(kOrig6140)    },
        { 0x0055DC5F, kNbArgs6140,  sizeof(kNbArgs6140)  },
        { 0x0055DC71, kNbRet6140,   sizeof(kNbRet6140)   },
        { 0x0055DA9E, kNbCode5_6140, sizeof(kNbCode5_6140) },
        { 0x0055DAA2, kNbTail6140,  sizeof(kNbTail6140)  },
        { 0x0055DA0D, kNbUser6140,  sizeof(kNbUser6140)  },
        { 0x0055D9AD, kNbThis6140,  sizeof(kNbThis6140)  },
    };
    const Site sitesC[] =
    {
        { 0x0055DFDF, kOrig2453,    sizeof(kOrig2453)    },
        { 0x0055DFC9, kNbArgs2453,  sizeof(kNbArgs2453)  },
        { 0x0055DFE4, kNbRet2453,   sizeof(kNbRet2453)   },
        { 0x0055DEC4, kNbFlag2453,  sizeof(kNbFlag2453)  },
    };
    if (g_check6138 && !VerifyAllSites(L"P68", sitesA, ARRAYSIZE(sitesA))) { return PatchResult::Mismatch; }
    if (g_check6140 && !VerifyAllSites(L"P68", sitesB, ARRAYSIZE(sitesB))) { return PatchResult::Mismatch; }
    if (g_keepNameOnDbFail && !VerifyAllSites(L"P68", sitesC, ARRAYSIZE(sitesC))) { return PatchResult::Mismatch; }

    int n = 0;
    if (g_check6138)        { if (!Hook::WriteCall(0x0055D8CE, &St_Name6138, 5)) { return PatchResult::Failed; } ++n; }
    if (g_check6140)        { if (!Hook::WriteCall(0x0055DC6C, &St_Name6140, 5)) { return PatchResult::Failed; } ++n; }
    if (g_keepNameOnDbFail) { if (!Hook::WriteCall(0x0055DFDF, &St_Keep2453, 5)) { return PatchResult::Failed; } ++n; }
    Log::Line(L"    P68: режим %s; площадок %d/3: 6138=%d 6140=%d 2453=%d; символы %s; 6140 только после 6138 с тем же именем=%d; "
              L"операторы (GM-флаг, как P47) без проверки=%d; строки не чаще 1/%d с",
              g_mode ? L"ОТКАЗ" : L"ЖУРНАЛ", n, g_check6138 ? 1 : 0, g_check6140 ? 1 : 0, g_keepNameOnDbFail ? 1 : 0,
              g_charset ? L"локали 7/8 + кодеки порта" : L"A-Z a-z 0-9", g_require6138 ? 1 : 0, g_operatorExempt ? 1 : 0, g_journalIntervalSec);
    return PatchResult::Applied;
}
