// Copyright (c) 2026 @sitxovski (Discord)
// p92_hostile_target_guard.cpp — ВРЕДНЫЙ ЭФФЕКТ НАВЫКА ИГРОКА ЛОЖИТСЯ ТОЛЬКО НА ВРАЖДЕБНОГО ИГРОКА (P92, волна bowfx, 26.10.2026).
//
// [ИСПРАВЛЕНИЕ] дефектов оригинала по задаче владельца 26.10: «навыки, которые должны вешаться только на мобов и враждебных
// игроков, можно применить к мирным игрокам». Протокол клиента НЕ меняется (пакеты и поля стоковые).
// Документ: AstoryServer/Docs/GameServer/hostile-target-guard-p92.md. Проверки: tools/verify_p92.py, стенд tools/stand_p92.
//
// ── ПРАВИЛО ОРИГИНАЛА (сервер, общий для всех путей) ──
//   sub_556DB0@0x556DB0 (CUserManager, a2 = исполнитель, a3 = цель, a4 = навык; 0 — нельзя). Режим боя — байт ИСПОЛНИТЕЛЯ
//   CUser+0x3E8D2 (биты: 1 дуэль — соперник dword +0x3E8D3 == цель+0xC; 2 свободный бой — «свои»: соулмейт dword +0x182B9,
//   клан word +0x18318, отряд word +0x1B4; 4 война — команда dword +0x3E8D3 против word цели +0x3F44C). Враждебность навыка —
//   SkillInfo[a4]+52 == 6 (у навыков хранителя ≥1201 — SoulGuarderSkillTable+46). a4 = −1 — «удар» (4201/4203): ровно
//   правило враждебного навыка (режим 0 — нельзя; дуэль — только соперник; свободный — не свои; война — не своя команда).
//   Режим ЦЕЛИ правило не смотрит. Полная таблица — документ §2.
//
// ── ДЫРЫ (реверс GameServer.c + сплошной скан образа, второй метод — стенд stand_p92 на настоящем коде) ──
//   S1 SkillState_SKILL_STATE_EXPLOSION_ARROW@0x486870 (состояние 173, навык 788 «Взрыв»: прок обычной атаки) — перебирает
//      ВСЕХ игроков 9 секторов в радиусе вокруг цели (или вокруг себя при само-проке), каждому 4102 + урон sub_43C690 +
//      смерть sub_4CB180 — БЕЗ sub_556DB0 (соседи CHIP_EFFECT 160 и LIGHT_BLOW 924 её зовут). Мирный прохожий получал урон;
//      при PvP-цели урон ловил и сам исполнитель (исключается только центр). Площадка 0x486B3A (8 б) — после стокового
//      «жертва ≠ центр», перед записью жертвы в запись 8009.
//   S2 SkillState_SKILL_GUARDIAN_NORMAL_ATTACK_AREA@0x486F20 (состояние 248, хранители 1216–1218 «학살자»: площадной прок
//      обычной атаки) — то же, без sub_556DB0; плюс прок 249. Площадка 0x48722A (8 б) — после «жертва ≠ цель, ≠ исполнитель».
//   S3 SkillState_SKILL_GUARDIAN_DAMAGE_REPLEX@0x486C20 (состояние 220, отражение хранителей 1203/1206/…) — sub_556DB0 зовётся
//      с ID СОСТОЯНИЯ 220, а у строки 220 SkillInfo+52 = 0 («не враждебный»): режим 0 — урон ВСЕМ игрокам 9 секторов (и самому
//      отражающему), дуэль — всем, КРОМЕ соперника, свободный бой — только своим, война — только своей команде. Правило
//      перевёрнуто. Площадка 0x486E1A (5 б, push 0DCh перед вызовом) → решение P92 вместо стокового вызова.
//   S4 sub_4283F0@0x4283F0 (8009 от NpcServer → 4102 и наложение/урон): запись «цель-игрок» (вид 1, «наложить» 1) владельца-
//      игрока GameServer применяет БЕЗ сверки. Сток NpcServer сверяет отношение САМ (sub_426000 — копия sub_556DB0 по зеркалу
//      режима из 4206) для ловушек 110/181/185 и эффектов 77/119 — по правилам оригинала дыры нет; S4 — страховка от
//      расхождения зеркала NpcServer (сверка по ИСТИНЕ GameServer). Только записи, пришедшие пакетом 8009 (адрес возврата
//      0x4314FF), — внутренние вызовы S1–S3/CHIP/LIGHT_BLOW уже сверены. Площадка 0x428453 (7 б).
//   S5 RecvChar_SkillUse@0x46F900 (5256): сверка целей sub_556DB0(…, навык) верна для навыков с +52 = 6, но в SkillInfo есть
//      вредный навык с +52 = 5 («любой игрок»): 1004 «Клеймо льда» («не позволяет ПРОТИВНИКУ ставить ловушки»). Сток пускал его
//      на любого мирного игрока, а в дуэли — на всех, КРОМЕ соперника. Список HostileSkills (по умолчанию 1004) — навыки,
//      которые сверяются как враждебные (a4 = −1). Площадка 0x46FCCB (8 б, push навыка перед вызовом).
//
// ── РЕШЕНИЕ ──
//   «Можно» = sub_556DB0(менеджер, исполнитель/владелец, жертва, −1) != 0 (стоковая функция; P42 C1 на её входе — тоже) и
//   жертва ≠ исполнитель (S1/S3; S2 сток уже исключает). Нельзя — жертва ПРОПУСКАЕТСЯ ровно как стоковый пропуск цикла
//   (нет 4102, урона, смерти, прока); S4 — запись 8009 пропускается целиком (не наложение и не 4102); S5 — отказ 5256 стоковой
//   веткой (v24 = 0). Исполнитель/жертва не находятся (GetUser) — решение стока. Mode=0 — только журнал (поведение стока).
//   Журнал P53 ac.other 121 (S1/S2/S3/S5: эффект на невраждебного не применён), 122 (S4: запись NpcServer отброшена),
//   123 (исключение — решение стока); строка в стоковый лог канала LogChannel; не чаще JournalIntervalSec на (исполнитель, площадка).
//
// ⚠⚠⚠ СМЕЩЕНИЯ ВО ВСТРОЕННОМ АССЕМБЛЕРЕ — ТОЛЬКО ЛИТЕРАЛЫ (C++-константа в `[reg + имя]` даёт АДРЕС).
#include "Patches.h"
#include <stdio.h>
#include <string.h>
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include "../AcJournal.h"

namespace
{
    const wchar_t* kSec = L"P92_HostileTargetGuard";            // секция patches.ini
    const wchar_t* kDefHostile = L"1004";                       // навыки 5256, сверяемые как враждебные

    // ── площадки ─────────────────────────────────────────────────────────────
    // S1 EXPLOSION_ARROW: mov cx,[ebp-4] ; mov [ebp-17h],cx (жертва → запись 8009 @+1)
    const DWORD kS1 = 0x00486B3A;  const BYTE kS1Orig[8] = { 0x66, 0x8B, 0x4D, 0xFC, 0x66, 0x89, 0x4D, 0xE9 };
    DWORD g_s1Back = 0x00486B42, g_s1Skip = 0x00486BF9;
    // S2 GUARDIAN_NORMAL_ATTACK_AREA: mov ax,[ebp-4] ; mov [ebp-2Bh],ax
    const DWORD kS2 = 0x0048722A;  const BYTE kS2Orig[8] = { 0x66, 0x8B, 0x45, 0xFC, 0x66, 0x89, 0x45, 0xD5 };
    DWORD g_s2Back = 0x00487232, g_s2Skip = 0x004870C2;
    // S3 GUARDIAN_DAMAGE_REPLEX: push 0DCh (первый аргумент стокового sub_556DB0(a2, жертва, 220))
    const DWORD kS3 = 0x00486E1A;  const BYTE kS3Orig[5] = { 0x68, 0xDC, 0x00, 0x00, 0x00 };
    DWORD g_s3Pass = 0x00486E46, g_s3Skip = 0x00486D4E;
    // S4 sub_4283F0: movzx eax, byte [ebp-7] ; cmp eax, 1 (байт «наложить» записи 8009)
    const DWORD kS4 = 0x00428453;  const BYTE kS4Orig[7] = { 0x0F, 0xB6, 0x45, 0xF9, 0x83, 0xF8, 0x01 };
    DWORD g_s4Back = 0x0042845A, g_s4Skip = 0x00428426;
    // S5 RecvChar_SkillUse: mov dx,[ebp-59Ch] ; push edx (навык — аргумент a4 sub_556DB0)
    const DWORD kS5 = 0x0046FCCB;  const BYTE kS5Orig[8] = { 0x66, 0x8B, 0x95, 0x64, 0xFA, 0xFF, 0xFF, 0x52 };
    DWORD g_s5Back = 0x0046FCD3;

    // соседи (только сверка — кадр, продолжения и пропуски такие, как разобраны)
    const BYTE kS1BackOrig[7] = { 0xC6, 0x85, 0x10, 0xFD, 0xFF, 0xFF, 0x00 };   // 0x486B42 mov byte [ebp-2F0h],0
    const BYTE kS1SkipOrig[5] = { 0xE9, 0xE1, 0xFD, 0xFF, 0xFF };               // 0x486BF9 jmp 0x4869DF (следующая жертва)
    const DWORD kS1Self = 0x00486B2A;                                          // movsx edx,[ebp-4] ; movsx eax,[ebp+8] ; cmp ; je 0x486BF9
    const BYTE kS1SelfOrig[16] = { 0x0F, 0xBF, 0x55, 0xFC, 0x0F, 0xBF, 0x45, 0x08, 0x3B, 0xD0, 0x0F, 0x84, 0xBF, 0x00, 0x00, 0x00 };
    const DWORD kS1Owner = 0x00486899;                                         // mov cx,[ebp+1Ch] ; mov [ebp-0Ah],cx (владелец a7 → запись @+14)
    const BYTE kS1OwnerOrig[8] = { 0x66, 0x8B, 0x4D, 0x1C, 0x66, 0x89, 0x4D, 0xF6 };
    const DWORD kS1This = 0x00486883;                                          // mov [ebp-2F4h],ecx
    const BYTE kS1ThisOrig[6] = { 0x89, 0x8D, 0x0C, 0xFD, 0xFF, 0xFF };
    const BYTE kS2BackOrig[7] = { 0xC6, 0x85, 0xF0, 0xFC, 0xFF, 0xFF, 0x00 };   // 0x487232 mov byte [ebp-310h],0
    const DWORD kS2Excl = 0x0048720D;                                          // жертва ≠ a3 (je 0x487225) и ≠ a2 (jne 0x48722A)
    const BYTE kS2ExclOrig[24] = { 0x0F, 0xBF, 0x55, 0xFC, 0x0F, 0xBF, 0x45, 0x0C, 0x3B, 0xD0, 0x74, 0x0C,
                                   0x0F, 0xBF, 0x4D, 0x08, 0x0F, 0xBF, 0x55, 0xFC, 0x3B, 0xCA, 0x75, 0x05 };
    const DWORD kS2SkipJmp = 0x00487225;                                       // jmp 0x4870C2 (стоковый пропуск)
    const BYTE kS2SkipJmpOrig[5] = { 0xE9, 0x98, 0xFE, 0xFF, 0xFF };
    const DWORD kS2This = 0x00486F33;                                          // mov [ebp-314h],ecx
    const BYTE kS2ThisOrig[6] = { 0x89, 0x8D, 0xEC, 0xFC, 0xFF, 0xFF };
    const DWORD kS3Call = 0x00486E1F;                                          // mov dx,[ebp-4];push edx;mov ax,[ebp+8];push eax;mov ecx,[ebp-2DCh];…;call 556DB0;movzx;test;jne 486E46;jmp 486D4E
    const BYTE kS3CallOrig[39] = { 0x66, 0x8B, 0x55, 0xFC, 0x52, 0x66, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0x24, 0xFD, 0xFF, 0xFF,
                                   0x8B, 0x51, 0x04, 0x8B, 0x4A, 0x34, 0xE8, 0x76, 0xFF, 0x0C, 0x00, 0x0F, 0xB6, 0xC0, 0x85, 0xC0,
                                   0x75, 0x05, 0xE9, 0x08, 0xFF, 0xFF, 0xFF };
    const DWORD kS4Rec = 0x0042843E;                                           // push 11h ; mov ecx,[ebp+8] ; add ecx,[ebp-1Ch] ; push ecx ; lea edx,[ebp-14h]
    const BYTE kS4RecOrig[15] = { 0x6A, 0x11, 0x8B, 0x4D, 0x08, 0x03, 0x4D, 0xE4, 0x51, 0x8D, 0x55, 0xEC, 0x52, 0xE8, 0xF0 };
    const BYTE kS4BackOrig[6] = { 0x0F, 0x85, 0x8D, 0x03, 0x00, 0x00 };        // 0x42845A jne 0x4287ED
    const BYTE kS4SkipOrig[6] = { 0x8B, 0x55, 0xE4, 0x83, 0xC2, 0x11 };        // 0x428426 mov edx,[ebp-1Ch] ; add edx,11h
    const DWORD kS4Call = 0x004314FA;                                          // call sub_4283F0 (8009, ConnectSocketMsgProcess)
    const BYTE kS4CallOrig[5] = { 0xE8, 0xF1, 0x6E, 0xFF, 0xFF };
    const DWORD kS5Call = 0x0046FCD3;                                          // … push ecx ; mov dx,[ebp+8] ; push edx ; mov eax,[ebp-5C8h] ; … ; call 556DB0
    const BYTE kS5CallOrig[40] = { 0x8B, 0x85, 0x70, 0xFD, 0xFF, 0xFF, 0x6B, 0xC0, 0x1D, 0x66, 0x8B, 0x8C, 0x05, 0xA5, 0xFD, 0xFF,
                                   0xFF, 0x51, 0x66, 0x8B, 0x55, 0x08, 0x52, 0x8B, 0x85, 0x38, 0xFA, 0xFF, 0xFF, 0x8B, 0x48, 0x04,
                                   0x8B, 0x49, 0x34, 0xE8, 0xB5, 0x70, 0x0E, 0x00 };
    const DWORD kCanAttackEntry = 0x00556DB0;                                  // вход sub_556DB0 (сток; с P42 — jmp на его стаб C1)

    typedef char  (__thiscall *FnCanAttack)(void* mgr, short a2, short a3, short a4);   // 0x556DB0
    typedef void* (__thiscall *FnGetUser)(void* mgr, short idx);                        // 0x5324A0
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);                // 0x569DF0
    const FnCanAttack CanAttack = (FnCanAttack)0x00556DB0;
    const FnGetUser   GetUser   = (FnGetUser)Srv::kGetUser;
    const FnSrvLog    SrvLog    = (FnSrvLog)Srv::kLog;

    constexpr int kOffMode      = 0x3E8D2;   // байт режима боя исполнителя
    constexpr int kOffUserIndex = 0x174;     // учётка
    constexpr int kOffSlot      = 0x18C;     // слот персонажа
    constexpr int kOffName      = 0x178;     // имя персонажа cp1251

    // ── настройки ────────────────────────────────────────────────────────────
    bool g_enabled = false;
    int  g_mode    = 1;              // 1 — не применять; 0 — только журнал (сток)
    int  g_journalIntervalSec = 10;
    int  g_logChannel = 0;
    BYTE g_hostile[1200] = {};       // 1 — навык 5256 сверяется как враждебный (читает стаб S5)
    DWORD g_nsRet = 0x004314FF;      // адрес возврата вызова sub_4283F0 из обработчика 8009 (читает стаб S4)

    P92_Stats g_stats = {};

    // Журнал: не чаще g_journalIntervalSec на (исполнитель, площадка); сброс при смене учётки в слоте.
    struct Sess { int userIndex; DWORD jLast[6]; int jSup[6]; };
    Sess g_sess[0x226] = {};
    CRITICAL_SECTION g_lock; bool g_lockReady = false;

    const char* SiteName(int site)
    {
        switch (site)
        {
        case 1: return "explosion-splash";
        case 2: return "guardian-area";
        case 3: return "guardian-reflect";
        case 4: return "npc-8009";
        case 5: return "skill-5256";
        }
        return "?";
    }

    int IndexOf(const BYTE* user)
    {
        int ui = -1;
        __try { if (user) { ui = *(const int*)(user + kOffUserIndex); } } __except (EXCEPTION_EXECUTE_HANDLER) { ui = -1; }
        return ui;
    }

    int ModeOf(const BYTE* user)
    {
        int m = -1;
        __try { if (user) { m = user[kOffMode]; } } __except (EXCEPTION_EXECUTE_HANDLER) { m = -1; }
        return m;
    }

    // Строка журнала и лога (с ограничителем). kind 121/122/123.
    void Report(BYTE kind, int site, const BYTE* owner, int ownerNum, int victim, int skill, int opcode)
    {
        if (ownerNum < 0 || ownerNum >= 0x226) { return; }
        const int ui = IndexOf(owner);
        const int mode = ModeOf(owner);
        DWORD now = GetTickCount();
        if (!now) { now = 1; }
        bool write = true; int sup = 0;
        if (g_lockReady) { EnterCriticalSection(&g_lock); }
        Sess& s = g_sess[ownerNum];
        if (s.userIndex != ui) { memset(&s, 0, sizeof(s)); s.userIndex = ui; }
        if (g_journalIntervalSec > 0 && s.jLast[site] && now - s.jLast[site] < (DWORD)g_journalIntervalSec * 1000)
        {
            ++s.jSup[site];
            write = false;
        }
        else { s.jLast[site] = now; sup = s.jSup[site]; s.jSup[site] = 0; }
        if (g_lockReady) { LeaveCriticalSection(&g_lock); }
        if (!write) { InterlockedIncrement(&g_stats.suppressed); return; }

        const char* act = kind == 123 ? "exception -> stock" : (g_mode ? "-> drop" : "(journal)");
        char detail[64];
        _snprintf_s(detail, sizeof(detail), _TRUNCATE, "P92 %s skill %d victim %d mode %d %s", SiteName(site), skill, victim, mode, act);
        __try
        {
            SrvLog(g_logChannel, "P92 HostileTargetGuard: %s skill %d by %s UserNum %d UserIndex %d (mode %d) on UserNum %d — target not hostile %s%s",
                   SiteName(site), skill, owner ? (const char*)(owner + kOffName) : "?", ownerNum, ui, mode, victim, act,
                   sup ? " (suppressed before)" : "");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        AcJournal::Event e;
        AcJournal::Clear(e, AcJournal::kOther, kind);
        e.opcode = opcode;
        e.userNum = (short)ownerNum;
        e.ip = P47_PeerIpv4(ownerNum);
        e.suppressed = sup;
        if (owner)
        {
            __try
            {
                e.userIndex = *(const int*)(owner + kOffUserIndex);
                e.charSlot  = owner[kOffSlot];
                AcJournal::CopyName(e, owner + kOffName);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        e.v[0] = skill;                       // item_code ← навык / состояние
        e.v[1] = victim;                      // value1    ← userNum жертвы
        e.v[2] = site * 1000 + (mode & 0xFF); // value2    ← площадка × 1000 + режим боя исполнителя
        AcJournal::CopyText(e, detail);
        if (AcJournal::Push(e)) { InterlockedIncrement(&g_stats.journaled); }
    }

    // Менеджер пользователей из this обработчика: [[this+4]+34h] (CSkillManager / CMonsterManager — общая разметка).
    void* MgrOf(const BYTE* self)
    {
        const BYTE* world = *(BYTE* const*)(self + 4);
        return *(void* const*)(world + 0x34);
    }

    // Враждебен ли victim исполнителю owner по правилу оригинала (a4 = −1). Ставит *known = false, если кого-то нет.
    bool HostileTo(void* mgr, int owner, int victim, bool* known, BYTE** ownerUser)
    {
        *known = false;
        *ownerUser = nullptr;
        BYTE* o = (BYTE*)GetUser(mgr, (short)owner);
        if (!o) { return true; }
        *ownerUser = o;
        if (!GetUser(mgr, (short)victim)) { return true; }
        *known = true;
        return CanAttack(mgr, (short)owner, (short)victim, -1) != 0;
    }
}

// Решение площадки. ebp — кадр хоста. S1–S4: 1 — применять (сток), 0 — пропустить жертву/запись.
// S5: значение аргумента a4 для sub_556DB0 (навык или −1).
extern "C" int __stdcall P92_Decide(int site, BYTE* ebp)
{
    if (site == 5)
    {
        const int skill = *(const WORD*)(ebp - 0x59C);
        if (!g_enabled) { return skill; }
        __try
        {
            const BYTE* self = *(BYTE* const*)(ebp - 0x5C8);
            void* mgr = MgrOf(self);
            const int caster = *(const short*)(ebp + 8);
            const int i = *(const int*)(ebp - 0x290);
            const int target = *(const short*)(ebp + 29 * i - 0x25B);
            InterlockedIncrement(&g_stats.checks[5]);
            const bool stockOk = CanAttack(mgr, (short)caster, (short)target, (short)skill) != 0;
            const bool newOk   = CanAttack(mgr, (short)caster, (short)target, -1) != 0;
            if (stockOk && !newOk)
            {
                InterlockedIncrement(g_mode ? &g_stats.refused[5] : &g_stats.wouldRefuse[5]);
                Report(121, 5, (const BYTE*)GetUser(mgr, (short)caster), caster, target, skill, 5256);
            }
            else if (!stockOk && newOk) { InterlockedIncrement(&g_stats.allowedNew[5]); }
            return g_mode ? -1 : skill;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedIncrement(&g_stats.faults);
            return skill;
        }
    }

    if (!g_enabled || site < 1 || site > 4) { return 1; }
    __try
    {
        const BYTE* self = nullptr;
        int owner = -1, victim = -1, skill = -1, opcode = AcJournal::kNone;
        switch (site)
        {
        case 1:   // EXPLOSION_ARROW: a3 состояние [ebp+0Ch], a7 владелец [ebp+1Ch], жертва [ebp-4]
            self = *(BYTE* const*)(ebp - 0x2F4);
            owner = *(const short*)(ebp + 0x1C); victim = *(const short*)(ebp - 4); skill = *(const short*)(ebp + 0xC);
            break;
        case 2:   // GUARDIAN_NORMAL_ATTACK_AREA: a2 исполнитель [ebp+8], a4 состояние [ebp+10h], жертва [ebp-4]
            self = *(BYTE* const*)(ebp - 0x314);
            owner = *(const short*)(ebp + 8); victim = *(const short*)(ebp - 4); skill = *(const short*)(ebp + 0x10);
            break;
        case 3:   // GUARDIAN_DAMAGE_REPLEX: a2 отражающий [ebp+8], a3 состояние [ebp+0Ch], жертва [ebp-4]
            self = *(BYTE* const*)(ebp - 0x2DC);
            owner = *(const short*)(ebp + 8); victim = *(const short*)(ebp - 4); skill = *(const short*)(ebp + 0xC);
            break;
        case 4:   // sub_4283F0 (8009): запись [ebp-14h]: +1 цель, +3 навык, +14 владелец
            self = *(BYTE* const*)(ebp - 0x3C);
            owner = *(const short*)(ebp - 6); victim = *(const short*)(ebp - 0x13); skill = *(const short*)(ebp - 0x11);
            opcode = 8009;
            break;
        }
        void* mgr = MgrOf(self);
        InterlockedIncrement(&g_stats.checks[site]);

        bool known = false; BYTE* ou = nullptr;
        bool allow;
        if (victim == owner)
        {
            // S1/S3: свой площадной урон по себе (сток S1 — при PvP-цели, S3 — всегда в режиме 0). S4 — само-наложение (сток).
            if (site == 4) { return 1; }
            ou = (BYTE*)GetUser(mgr, (short)owner);
            known = ou != nullptr;
            allow = !known;
            if (known) { InterlockedIncrement(&g_stats.selfSkip); }
        }
        else
        {
            allow = HostileTo(mgr, owner, victim, &known, &ou);
        }

        if (site == 3)
        {
            // Сток S3: sub_556DB0(a2, жертва, 220) — перевёрнутое правило; решение P92 заменяет его (Mode=1).
            const bool stockOk = CanAttack(mgr, (short)owner, (short)victim, (short)skill) != 0;
            if (!known) { allow = stockOk; }
            if (stockOk && !allow)
            {
                InterlockedIncrement(g_mode ? &g_stats.refused[3] : &g_stats.wouldRefuse[3]);
                Report(121, 3, ou, owner, victim, skill, opcode);
            }
            else if (!stockOk && allow) { InterlockedIncrement(&g_stats.allowedNew[3]); }
            return g_mode ? (allow ? 1 : 0) : (stockOk ? 1 : 0);
        }

        if (!known) { InterlockedIncrement(&g_stats.noUser); return 1; }
        if (allow) { return 1; }
        InterlockedIncrement(g_mode ? &g_stats.refused[site] : &g_stats.wouldRefuse[site]);
        Report(site == 4 ? 122 : 121, site, ou, owner, victim, skill, opcode);
        return g_mode ? 0 : 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        InterlockedIncrement(&g_stats.faults);
        __try
        {
            if (site == 3)
            {
                // исключение в S3 — решение стока (стоковый вызов с 220)
                const BYTE* self = *(BYTE* const*)(ebp - 0x2DC);
                const int owner = *(const short*)(ebp + 8);
                Report(123, 3, nullptr, owner, *(const short*)(ebp - 4), *(const short*)(ebp + 0xC), AcJournal::kNone);
                return CanAttack(MgrOf(self), (short)owner, *(const short*)(ebp - 4), *(const short*)(ebp + 0xC)) != 0 ? 1 : 0;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return 1;
    }
}

extern "C" __declspec(dllexport) void __stdcall P92_GetStats(P92_Stats* out)
{
    if (out) { *out = g_stats; }
}

namespace
{
    // S1. Вход jmp из 0x486B3A: жертва ≠ центр (сток сверил). eax/ecx/edx на продолжении и пропуске мёртвые.
    __declspec(naked) void St_S1()
    {
        __asm
        {
            push  ebp
            push  1
            call  P92_Decide
            test  eax, eax
            jz    Skip1
            mov   cx, word ptr [ebp-4]              // замещённое
            mov   word ptr [ebp-17h], cx            // замещённое: жертва → запись 8009 @+1
            jmp   dword ptr [g_s1Back]              // 0x486B42
        Skip1:
            jmp   dword ptr [g_s1Skip]              // 0x486BF9 — следующая жертва (сток)
        }
    }
    // S2. Вход jmp из 0x48722A (жертва ≠ цель и ≠ исполнитель).
    __declspec(naked) void St_S2()
    {
        __asm
        {
            push  ebp
            push  2
            call  P92_Decide
            test  eax, eax
            jz    Skip2
            mov   ax, word ptr [ebp-4]              // замещённое
            mov   word ptr [ebp-2Bh], ax            // замещённое
            jmp   dword ptr [g_s2Back]              // 0x487232
        Skip2:
            jmp   dword ptr [g_s2Skip]              // 0x4870C2
        }
    }
    // S3. Вход jmp из 0x486E1A вместо стокового вызова sub_556DB0(a2, жертва, 220): стек ещё не тронут.
    __declspec(naked) void St_S3()
    {
        __asm
        {
            push  ebp
            push  3
            call  P92_Decide
            test  eax, eax
            jz    Skip3
            jmp   dword ptr [g_s3Pass]              // 0x486E46 — урон жертве (сток после «можно»)
        Skip3:
            jmp   dword ptr [g_s3Skip]              // 0x486D4E — следующая жертва (сток после «нельзя»)
        }
    }
    // S4. Вход jmp из 0x428453 (запись 8009 скопирована в [ebp-14h]). Быстрый отсев в стабе: только пакет NpcServer
    //   (адрес возврата 0x4314FF), вид 1 (игрок), «наложить» 1, владелец ≠ цель. На продолжении флаги — от cmp, как у стока.
    __declspec(naked) void St_S4()
    {
        __asm
        {
            mov   eax, dword ptr [ebp+4]
            cmp   eax, dword ptr [g_nsRet]
            jne   Plain4
            cmp   byte ptr [ebp-14h], 1
            jne   Plain4
            cmp   byte ptr [ebp-7], 1
            jne   Plain4
            mov   ax, word ptr [ebp-6]
            cmp   ax, word ptr [ebp-13h]
            je    Plain4
            push  ebp
            push  4
            call  P92_Decide
            test  eax, eax
            jz    Skip4
        Plain4:
            movzx eax, byte ptr [ebp-7]             // замещённое
            cmp   eax, 1                            // замещённое (флаги для jne 0x42845A → 0x4287ED)
            jmp   dword ptr [g_s4Back]              // 0x42845A
        Skip4:
            jmp   dword ptr [g_s4Skip]              // 0x428426 — следующая запись
        }
    }
    // S5. Вход jmp из 0x46FCCB: навык не из списка — сток (push навыка); из списка — P92_Decide (−1 или навык).
    __declspec(naked) void St_S5()
    {
        __asm
        {
            movzx eax, word ptr [ebp-59Ch]
            cmp   eax, 1199
            ja    Plain5
            movzx ecx, byte ptr [g_hostile + eax]
            test  ecx, ecx
            jz    Plain5
            push  ebp
            push  5
            call  P92_Decide
            push  eax                               // a4 для sub_556DB0
            jmp   dword ptr [g_s5Back]              // 0x46FCD3
        Plain5:
            mov   dx, word ptr [ebp-59Ch]           // замещённое
            push  edx                               // замещённое
            jmp   dword ptr [g_s5Back]
        }
    }

    // Разбор HostileSkills: «a-b;c;d». Возврат: число навыков; −1 — синтаксическая ошибка.
    int ParseList(const wchar_t* s, BYTE* out)
    {
        memset(out, 0, 1200);
        int count = 0;
        const wchar_t* p = s;
        while (*p)
        {
            while (*p == L';' || *p == L',' || *p == L' ' || *p == L'\t') { ++p; }
            if (!*p) { break; }
            if (*p < L'0' || *p > L'9') { return -1; }
            int a = 0;
            while (*p >= L'0' && *p <= L'9') { a = a * 10 + (*p - L'0'); if (a > 100000) { return -1; } ++p; }
            int b = a;
            if (*p == L'-')
            {
                ++p;
                if (*p < L'0' || *p > L'9') { return -1; }
                b = 0;
                while (*p >= L'0' && *p <= L'9') { b = b * 10 + (*p - L'0'); if (b > 100000) { return -1; } ++p; }
            }
            if (*p && *p != L';' && *p != L',' && *p != L' ' && *p != L'\t') { return -1; }
            if (b < a) { return -1; }
            for (int c = a; c <= b; ++c)
            {
                if (c < 0 || c >= 1200) { continue; }   // навыки хранителя (≥1200) сток и так сверяет своей таблицей
                if (!out[c]) { out[c] = 1; ++count; }
            }
        }
        return count;
    }
}

PatchResult P92_HostileTargetGuard()
{
    if (!Config::GetBool(kSec, L"Enabled", true)) { g_enabled = false; return PatchResult::Disabled; }
    g_mode = Config::GetInt(kSec, L"Mode", 1) ? 1 : 0;
    const bool splash  = Config::GetBool(kSec, L"SplashSites", true);
    const bool reflect = Config::GetBool(kSec, L"ReflectSite", true);
    const bool npcRec  = Config::GetBool(kSec, L"NpcRecordSite", true);
    g_journalIntervalSec = Config::GetInt(kSec, L"JournalIntervalSec", 10);
    if (g_journalIntervalSec < 0 || g_journalIntervalSec > 3600) { g_journalIntervalSec = 10; }
    g_logChannel = Config::GetInt(kSec, L"LogChannel", 0);
    if (g_logChannel < 0 || g_logChannel > 60) { g_logChannel = 0; }
    wchar_t list[512] = L"";
    Config::GetStr(kSec, L"HostileSkills", kDefHostile, list, ARRAYSIZE(list));
    int nHostile = ParseList(list, g_hostile);
    if (nHostile < 0)
    {
        Log::Line(L"    P92: HostileSkills=\"%s\" не разобран — взят список по умолчанию \"%s\"", list, kDefHostile);
        lstrcpynW(list, kDefHostile, ARRAYSIZE(list));
        nHostile = ParseList(list, g_hostile);
    }

    // ── сверка ВСЕХ площадок и соседей ДО первой записи ─────────────────────
    Site check[24];
    int k = 0;
    check[k++] = { kS1, kS1Orig, sizeof(kS1Orig) };
    check[k++] = { g_s1Back, kS1BackOrig, sizeof(kS1BackOrig) };
    check[k++] = { g_s1Skip, kS1SkipOrig, sizeof(kS1SkipOrig) };
    check[k++] = { kS1Self, kS1SelfOrig, sizeof(kS1SelfOrig) };
    check[k++] = { kS1Owner, kS1OwnerOrig, sizeof(kS1OwnerOrig) };
    check[k++] = { kS1This, kS1ThisOrig, sizeof(kS1ThisOrig) };
    check[k++] = { kS2, kS2Orig, sizeof(kS2Orig) };
    check[k++] = { g_s2Back, kS2BackOrig, sizeof(kS2BackOrig) };
    check[k++] = { kS2Excl, kS2ExclOrig, sizeof(kS2ExclOrig) };
    check[k++] = { kS2SkipJmp, kS2SkipJmpOrig, sizeof(kS2SkipJmpOrig) };
    check[k++] = { kS2This, kS2ThisOrig, sizeof(kS2ThisOrig) };
    check[k++] = { kS3, kS3Orig, sizeof(kS3Orig) };
    check[k++] = { kS3Call, kS3CallOrig, sizeof(kS3CallOrig) };
    check[k++] = { kS4, kS4Orig, sizeof(kS4Orig) };
    check[k++] = { kS4Rec, kS4RecOrig, sizeof(kS4RecOrig) };
    check[k++] = { g_s4Back, kS4BackOrig, sizeof(kS4BackOrig) };
    check[k++] = { g_s4Skip, kS4SkipOrig, sizeof(kS4SkipOrig) };
    check[k++] = { kS4Call, kS4CallOrig, sizeof(kS4CallOrig) };
    check[k++] = { kS5, kS5Orig, sizeof(kS5Orig) };
    check[k++] = { kS5Call, kS5CallOrig, sizeof(kS5CallOrig) };
    if (!VerifyAllSites(L"P92", check, k)) { g_enabled = false; return PatchResult::Mismatch; }
    {
        // вход sub_556DB0: сток (push ebp; mov ebp,esp; sub esp,1Ch) или jmp на стаб P42 C1 — оба годятся
        const BYTE* p = (const BYTE*)kCanAttackEntry;
        if (!(p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC) && p[0] != 0xE9)
        {
            Log::Line(L"    P92: вход sub_556DB0 @0x%08X не сток и не jmp (%02X %02X %02X) — не ставится", kCanAttackEntry, p[0], p[1], p[2]);
            g_enabled = false;
            return PatchResult::Mismatch;
        }
    }
    if (!splash && !reflect && !npcRec && nHostile <= 0) { g_enabled = false; return PatchResult::Disabled; }

    if (!g_lockReady) { InitializeCriticalSection(&g_lock); g_lockReady = true; }
    memset(g_sess, 0, sizeof(g_sess));
    g_enabled = true;

    // ── запись ──────────────────────────────────────────────────────────────
    if (splash && !Hook::WriteJmp(kS1, (void*)&St_S1, sizeof(kS1Orig))) { return PatchResult::Failed; }
    if (splash && !Hook::WriteJmp(kS2, (void*)&St_S2, sizeof(kS2Orig))) { return PatchResult::Failed; }
    if (reflect && !Hook::WriteJmp(kS3, (void*)&St_S3, sizeof(kS3Orig))) { return PatchResult::Failed; }
    if (npcRec && !Hook::WriteJmp(kS4, (void*)&St_S4, sizeof(kS4Orig))) { return PatchResult::Failed; }
    if (nHostile > 0 && !Hook::WriteJmp(kS5, (void*)&St_S5, sizeof(kS5Orig))) { return PatchResult::Failed; }

    Log::Line(L"    P92: режим %s; правило — sub_556DB0(исполнитель, жертва, -1) (как удар 4201): S1 взрыв 173 @0x%08X %s, "
              L"S2 площадной прок хранителя 248 @0x%08X %s, S3 отражение 220 @0x%08X %s, S4 записи 8009 NpcServer @0x%08X %s",
              g_mode ? L"НЕ ПРИМЕНЯТЬ" : L"ЖУРНАЛ", kS1, splash ? L"да" : L"нет", kS2, splash ? L"да" : L"нет",
              kS3, reflect ? L"да" : L"нет", kS4, npcRec ? L"да" : L"нет");
    Log::Line(L"    P92: S5 5256 @0x%08X — навыки, сверяемые как враждебные: %d (\"%s\")%s; журнал ac.other 121/122/123 не чаще 1/%d с "
              L"на (исполнитель, площадка); канал лога %d", kS5, nHostile > 0 ? nHostile : 0, list,
              nHostile > 0 ? L"" : L" — площадка не ставится", g_journalIntervalSec, g_logChannel);
    return PatchResult::Applied;
}
