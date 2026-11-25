// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
//  P121 — [ИСПРАВЛЕНИЕ] ПРЕДМЕТ СМЕНЫ ИМЕНИ НЕ ТРАТИТСЯ ЧЕРЕЗ 5450 (09.11.2026, пачка 20, баг 8; решение владельца «Да, P121»).
//  Разбор: Reports/batch20/rename/REPORT.md; документ AstoryServer/Docs/GameServer/char-rename-guard-p121.md.
//
//  ── СТОК (GameServer e7b4ac38 = Indun = Ch2; сток 4e20f0ad — те же байты) ──
//  Предмет смены имени — Function_Table категория (+8) 111 (Special_ItemList 357 «Character name change item»). Оригинальный клиент
//  его через 5450 не шлёт: подтип 111 ведёт в окно 7900 и пакеты 6138/6140 (RecvClient_CharNameCheck / RecvClient_CharNameChange).
//  Но 5450 → Char_FunctionItem_Use@0x4ED780 подтип 111 не отвергает: switch(+8 − 15) @0x4EDEB3…0x4EDEE5, индекс 96 → байт 11 →
//  default 0x4EE5A1 (LABEL_69) → DB 2140 (UPInvenUse) — предмет списан, JoyLog1.UseFunctional, имя не меняется. Так теряли 357
//  игроки клиента порта до alpha-7.0.0 включительно (у него подтипа 111 нет — он шлёт 5450): 4 траты на dev 20.10–08.11.
//
//  ── ЧТО ДЕЛАЕТ P121 (6 б, протокол не меняется) ──
//  Площадка 0x4EDEB3 — `mov [ebp-2FCh],eax` (eax = категория +8, до вычитания 15) → заглушка. Категория == Subtype (ключ ini,
//  по умолчанию 111) → [ebp-121h] = RefuseCode (по умолчанию 0) и общий выход отказа 0x4EF0C3: 5451 с этим кодом,
//  в DBManager ничего не уходит, предмет не тратится. Клиент (и alpha-7.0.0, и оригинал, `netRecvItemBuffApply@0xF23C60`)
//  переводит код 0 в нотис 12837 «Не удалось использовать инструмент» / «Failed in using a Functional Item». Иначе — штатная
//  инструкция и продолжение 0x4EDEB9. Смена имени через 6138/6140 не затронута (другие обработчики).
//  Журнал: FuncLog сервера (канал 8) — строка на каждый отказ. Нарушения античита нет (старый клиент делает это честно).
//
//  ── СОСЕДИ В Char_FunctionItem_Use (совместимость, verify_p121) ──
//  P75 0x4EDDB5/0x4EDDC7/0x4EDDCC (до switch; только код 558 — категория 6; путь 558 через 0x4EDEB3 проходит со своей категорией),
//  P102 S5 0x4EDDCE…0x4EDDFC, P65 0x4EDD7B…0x4EDDA4, P100 0x4EDD35, P15 0x4ED9F5, P117 0x4ED9CF (чтение) и 0x4EE25B (case 120 —
//  ПОСЛЕ switch: категория 120 проходит P121 без изменений), P97 0x4EE218/0x4EE221, P103 S2 0x4EE5A1 (вход default: категория 111
//  до него больше не доходит; при P121 Enabled=0 — как раньше). Общий выход 0x4EF0C3 (P102 S5, P103 S2, P117) только читается.
//  Площадок в 0x4EDEB3…0x4EDEB9 нет ни у одного патча.
//  Откат: patches.ini [P121_CharRenameGuard] Enabled=0 — проверка смены имени выключена (сток для категории 111).
//  ★ 22.11.2026 (P129, А6.12, ревизии 60/62): площадка 0x4EDEB3 — ОБЩАЯ ТОЧКА с P129. При включённом P129 ([P129_ChatLog]
//   Enabled=1 и ShoutItemHook=1) она ставится и при Enabled=0 P121 (тогда P121 возвращает Disabled, но заглушка стоит). Категории
//   0x31/0x32 (крик предметом) заглушка отдаёт P129_ShoutRequestGate: заглушка чата и Mode=1 → тот же отказ 0x4EF0C3 (5451 с ОБЩИМ
//   RefuseCode P121, по умолчанию 0 → нотис 12837), предмет цел; строки [P121] в FuncLog на такой отказ нет (журнал — chat.message).
//   Совсем без площадки — Enabled=0 у P121 И (P129 выключен или ShoutItemHook=0).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"

namespace
{
    const wchar_t* kSec = L"P121_CharRenameGuard";            // секция patches.ini

    constexpr DWORD kSite   = 0x004EDEB3;                     // mov [ebp-2FCh],eax — категория +8 Function_Table
    constexpr DWORD kBack   = 0x004EDEB9;                     // продолжение стока: mov ecx,[ebp-2FCh]; sub ecx,0Fh
    constexpr DWORD kRefuse = 0x004EF0C3;                     // общий выход отказа: 5451 с кодом [ebp-121h]
    const BYTE kSiteOrig[6] = { 0x89, 0x85, 0x04, 0xFD, 0xFF, 0xFF };
    const BYTE kBackOrig[9] = { 0x8B, 0x8D, 0x04, 0xFD, 0xFF, 0xFF, 0x83, 0xE9, 0x0F };                 // mov ecx,[ebp-2FCh]; sub ecx,0Fh
    // 0x4EDEA8: mov edx,[5F5E70h]; movzx eax, byte [edx+ecx+8] — eax на площадке = категория строки Function_Table
    const BYTE kLoadCat[11] = { 0x8B, 0x15, 0x70, 0x5E, 0x5F, 0x00, 0x0F, 0xB6, 0x44, 0x0A, 0x08 };
    constexpr DWORD kLoadCatSite = 0x004EDEA8;
    // 0x4EDEC8: cmp [ebp-2FCh],0C5h; ja 0x4EE5A1 — default switch (сюда шла категория 111)
    const BYTE kSwitch[16] = { 0x81, 0xBD, 0x04, 0xFD, 0xFF, 0xFF, 0xC5, 0x00, 0x00, 0x00, 0x0F, 0x87, 0xC9, 0x06, 0x00, 0x00 };
    constexpr DWORD kSwitchSite = 0x004EDEC8;
    const BYTE kRefuseOrig[7] = { 0x0F, 0xB6, 0x85, 0xDF, 0xFE, 0xFF, 0xFF };           // movzx eax, byte [ebp-121h]
    // 0x4ED9CF: mov [ebp-20Ch],eax (CUser из sub_5324A0); cmp dword [ebp-20Ch],0 — сток не пускает дальше пустого (как у P117)
    const BYTE kUserStore[13] = { 0x89, 0x85, 0xF4, 0xFD, 0xFF, 0xFF, 0x83, 0xBD, 0xF4, 0xFD, 0xFF, 0xFF, 0x00 };
    constexpr int kOffUserIdx = 0x174;                        // CUser: Userindex (учётка)
    constexpr int kOffName = 0x178;                           // CUser: имя персонажа

    typedef void (__cdecl* FnSrvLog)(int cat, const char* fmt, ...);
    const FnSrvLog SrvLog = (FnSrvLog)Srv::kLog;
    constexpr int kLogCatFunc = 8;                            // Log\Log_Func\FuncLog_<дата>.txt

    int g_subtype = 111;                                      // категория, которую 5450 не принимает (ключ Subtype)
    BYTE g_code = 0;                                          // код 5451 отказа (0 → клиент 12837)
    bool g_funcLog = true;
    bool g_renameOn = true;                                   // ★ P129: собственная проверка P121 включена (Enabled=1)
    DWORD g_back = kBack;
    DWORD g_refuse = kRefuse;
    P121_Stats g_stats = {};

}

// C-часть заглушки: 1 — отказ (код g_code), 0 — сток. ebp — кадр Char_FunctionItem_Use, cat — категория +8.
extern "C" int __stdcall P121_Gate(BYTE* ebp, int cat)
{
    __try
    {
        InterlockedIncrement(&g_stats.seen);
        // ★ P129 (А6.12, ревизия 60 Н-5): крик предметом (категории 0x31/0x32) под заглушкой чата — отказ ДО расхода (тот же
        //   общий выход 0x4EF0C3: 5451 с кодом g_code, в DBManager ничего не уходит). Решает P129_ShoutRequestGate (P129 выключен — 0).
        if ((cat == 0x31 || cat == 0x32) && P129_ShoutRequestGate(ebp)) { return 1; }
        if (!g_renameOn || cat != g_subtype) { return 0; }
        InterlockedIncrement(&g_stats.refused);
        if (g_funcLog)
        {
            const BYTE* user = *(BYTE* const*)(ebp - 0x20C);
            const int code = *(const int*)(ebp - 0x204);
            SrvLog(kLogCatFunc, "\t[P121] Rename item via 5450 refused..! %s, UserIndex:%d, Code:%d, SubType:%d -> 5451 %d",
                   user ? (const char*)(user + kOffName) : "?", user ? *(const int*)(user + kOffUserIdx) : -1, code, cat, (int)g_code);
        }
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
    }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall P121_GetStats(P121_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // Вместо `mov [ebp-2FCh],eax` перед switch по категории.
    __declspec(naked) void St_RenameGate()
    {
        __asm
        {
            pushfd
            pushad
            push  eax                                   // категория +8
            push  ebp
            call  P121_Gate
            test  eax, eax
            jnz   refuse
            popad
            popfd
            mov   dword ptr [ebp - 2FCh], eax
            jmp   dword ptr [g_back]                  // 0x4EDEB9
        refuse:
            popad
            popfd
            mov   al, byte ptr [g_code]
            mov   byte ptr [ebp - 121h], al           // 5451 код
            jmp   dword ptr [g_refuse]                // 0x4EF0C3 — общий выход: 5451 клиенту, в БД ничего
        }
    }
}

PatchResult P121_CharRenameGuard()
{
    // ★ P129 (А6.12): площадка нужна и при Enabled=0, если P129 хочет отказывать крику предметом до расхода (общая точка).
    g_renameOn = Config::GetBool(kSec, L"Enabled", true);
    const bool p129 = P129_ShoutGateWanted();
    if (!g_renameOn && !p129) { return PatchResult::Disabled; }
    g_funcLog = Config::GetBool(kSec, L"FuncLog", true);
    const int code = Config::GetInt(kSec, L"RefuseCode", 0);
    g_code = (BYTE)((code >= 0 && code <= 255) ? code : 0);
    const int sub = Config::GetInt(kSec, L"Subtype", 111);
    g_subtype = (sub >= 0 && sub <= 255) ? sub : 111;
    const Site sites[] =
    {
        { kSite,        kSiteOrig,   sizeof(kSiteOrig)   },
        { kBack,        kBackOrig,   sizeof(kBackOrig)   },
        { kLoadCatSite, kLoadCat,    sizeof(kLoadCat)    },
        { kSwitchSite,  kSwitch,     sizeof(kSwitch)     },
        { kRefuse,      kRefuseOrig, sizeof(kRefuseOrig) },
        { 0x004ED9CF,   kUserStore,  sizeof(kUserStore)  },
    };
    if (!VerifyAllSites(L"P121", sites, ARRAYSIZE(sites))) { return PatchResult::Mismatch; }
    if (!Hook::WriteJmp(kSite, &St_RenameGate, 6)) { return PatchResult::Failed; }
    if (!g_renameOn)
    {
        Log::Line(L"    P121: Enabled=0 — проверка смены имени ВЫКЛ; площадка 0x%08X поставлена только ради P129 (крик предметом под заглушкой "
                  L"-> 5451 код %d, предмет цел)", kSite, (int)g_code);
        return PatchResult::Disabled;
    }
    Log::Line(L"    P121: Char_FunctionItem_Use @0x%08X (6 б) -> заглушка 0x%08X: категория %d через 5450 -> 5451 код %d, предмет цел",
              kSite, (DWORD)&St_RenameGate, g_subtype, (int)g_code);
    return PatchResult::Applied;
}
