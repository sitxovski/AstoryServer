// Copyright (c) 2026 @sitxovski (Discord)
// ─────────────────────────────────────────────────────────────────────────────
//  P11 — СЕРВЕРНЫЕ источники анонса 6131. Сервер решает сам, клиенту не доверяем.
//
//  Четыре точки (все проверены дизассемблером стока; ни один rel-переход во всей
//  .text не ведёт ВНУТРЬ этих площадок — проверено полным перебором кодировок):
//
//   1 PICK    CharItemPicking@0x4D43A0, ЕДИНЫЙ эпилог 0x4D5E61 (5 б), возврат 0x4D5E66.
//             Компилятор продублировал LABEL_109 трижды, но эпилог один: на него
//             ведут 15 jmp + fallthrough. Успех = byte[ebp-0x0B4] == 1 (в ctor
//             sub_46C6C0 поле инициализируется нулём, поэтому ранние выходы безопасны).
//   2 GACHA   Recv_GachaItemUse@0x4F48C0, хвост успешной ветки 0x4F5637 (5 б: add esp,0x1C; jmp).
//             ★ Анонсируем ВЫИГРЫШ [ebp-0x0D4], а НЕ вскрытую коробку [ebp-0x84]:
//             в лог-строке «Code=%d, Gacha=%d» Code — приз (заполняется рулеткой
//             sub_5329A0 из гача-таблицы), Gacha — использованная коробка.
//   3 PGACHA  Recv_UserPrimiumGaChaReward@0x4F72B0, 0x4F766E (5 б) перед DB-2555.
//             ⚠ Код награды приходит ОТ КЛИЕНТА (сервер валидирует его sub_532A90 и
//             флагом item+36==3) — уровень доверия ниже двух предыдущих источников.
//             Аргументы DB-вызова уже на стеке -> оборачиваем pushad/popad.
//   4 REFINE  CharShellItemUpgrade_0@0x4FEE50, 0x500602 (7 б), возврат 0x500609.
//   5 REFINE-PRE  ВХОД ВЕТКИ НЕУДАЧИ той же функции, 0x4FFFC5 (7 б), возврат 0x4FFFCC.
//             ★ Добавлено 2026-08-06 после живого теста. Ветка неудачи ДО схождения
//             с веткой успеха ОБНУЛЯЕТ ступень и процент прямо в записи предмета
//             (0x500009 `mov byte [ebp-0x208],0` / 0x500010 `mov word [ebp-0x205],0`,
//             и второй такой же блок 0x500080/0x500087), поэтому хук №4, стоящий
//             ПОСЛЕ них, видел `Lv 0 Pct 0` и анонс неудачи резался порогом.
//             Здесь снимаем ступень/процент ДО броска в g_pre[userIdx]; хук №4
//             при ok==0 берёт снимок, считает порог по нему и кладёт его в 6131.
//             ⚠ Сброс в +0 происходит НЕ всегда: только при виде улучшения 2
//             (`[ebp-0x2C0]==2`, купон) либо при виде 1, когда счётчик попыток
//             упёрся в предел и ItemTable[+0x24]==3. В «несбрасывающем» случае
//             (0x5000AB `mov byte [ebp-0x271],1`) снимок просто равен текущему.
//
//  ★★★ ЗАТОЧКА — УРОВНИ vs ПРОЦЕНТЫ (решение юзера: считать по ступени, показывать %):
//    item+24 BYTE — ступень 0..20 (счётчик успешных попыток), ПОРОГ считаем по ней;
//    item+27 WORD — НАКОПЛЕННЫЙ ПРОЦЕНТ, ИМЕННО ЕГО ВИДИТ ИГРОК. Клиент печатает
//      `if (slot[24]) sprintf(buf, "+%d%%", Util_Identity16(*(WORD*)(slot+27)))`
//      (item_inventory.c:4173 и ещё 9 мест; Util_Identity16 = `return a1`).
//    Процент накапливает СЕРВЕР: item+27 += ItemUpgrade.txt[+8] + бонус купона,
//    то есть зависит от материалов и из ступени НЕ выводится ⇒ считать его на
//    клиенте нельзя, сервер обязан слать фактическое значение.
//
//  РАСКЛАДКА ТЕЛА 6131 (44 б). Первые 24 байта — как в оригинале, поэтому СТОКОВЫЙ
//  клиент разбирает пакет штатно; байты 24+ он игнорирует (Recv_ItemFound читает 24).
//      +0  DWORD  код предмета
//      +4  char[20] имя игрока (cp1251, берётся С СЕРВЕРА из CUser+376)
//      +24 BYTE   тег источника: 0 legacy/6616, 1 подбор, 2 гача, 3 премиум-гача,
//                 4 заточка-успех, 5 заточка-неудача
//      +25 BYTE   ступень заточки (item+24)
//      +26 WORD   процент заточки (item+27)
//      +28 BYTE   признак неудачи (1)
//      +29..43    нули
//  ⚠ ОГРАНИЧЕНИЕ: ОРИГИНАЛЬНЫЙ клиент покажет любой такой анонс ЗЕЛЁНЫМ и отсеет
//    по «грейд >= 3» (это его собственный фильтр в Recv_ItemFound). Красный цвет и
//    проценты видит только наш порт. Менять протокол ради этого не стали.
// ─────────────────────────────────────────────────────────────────────────────
#include "Patches.h"
#include "../SrvApi.h"
#include "../Hook.h"
#include "../Log.h"
#include "../Config.h"
#include <string.h>
#include <stdlib.h>

namespace
{
    // ── указатели на функции сервера ────────────────────────────────────────
    typedef int   (__cdecl    *FnIsItemCode)(int code);
    typedef BYTE* (__thiscall *FnGetUser)(void* mgr, short idx);
    typedef int   (__thiscall *FnSendAllInMap)(void* mgr, short op, short len, void* buf, int flag);
    typedef int   (__thiscall *FnSendSector)(void* mgr, short idx, short op, short len, void* buf, int flag);
    typedef void  (__cdecl    *FnSrvLog)(int cat, const char* fmt, ...);

    const FnIsItemCode   SrvIsItemCode   = (FnIsItemCode)Srv::kIsItemCode;
    // ★★★ 2026-08-13 (rarechain-agent). Тот же пробел, что чинили в P01: код предмета живёт
    //   в ДВУХ серверных таблицах — item_list (20551..dword_5F5EAC, sub_532A90) и sowell_list
    //   (7001..dword_5F5EA0, sub_532AE0). Клиентский критерий редкости
    //   (`CItemManager_NotifyItemInfo@0xD0C8F0`, item_inventory.c:39524-39536) самоцветы
    //   ПРИЗНАЁТ: грейд берётся из `sowelRecord->dropColorIndex[0]`, фильтра по типу нет.
    //   P11 же проверял только kIsItemCode -> любой самоцвет отсекался как `SKIP Reason 1`
    //   (SKIP_BADCODE) ЕЩЁ ДО проверки редкости. Живой след: ItemLog 13.08 16:04:55
    //   `ServerNotice IN Src 2 Code 9640` -> `SKIP … Reason 1` (код 9640 = sowell_list).
    //   Сегодня это латентно (PickupEnabled=0, GachaEnabled=0, а в PrimiumGaChaTable
    //   самоцветов нет), но при включении подбора/гачи анонс самоцветов терялся бы МОЛЧА.
    const FnIsItemCode   SrvIsSowelCode  = (FnIsItemCode)Srv::kIsSowelCode;
    const FnGetUser      SrvGetUser      = (FnGetUser)Srv::kGetUser;
    const FnSendAllInMap SrvSendAllInMap = (FnSendAllInMap)Srv::kSendAllInMap;
    const FnSendSector   SrvSendSector   = (FnSendSector)Srv::kSendSectorAll;
    const FnSrvLog       SrvLog          = (FnSrvLog)Srv::kLog;

    const char kFmtIn[]   = "ServerNotice\tIN\tSrc\t%d\tCode\t%d\tUser\t%d\tLv\t%d\tPct\t%d";
    const char kFmtSkip[] = "ServerNotice\tSKIP\tSrc\t%d\tCode\t%d\tUser\t%d\tReason\t%d";
    const char kFmtOk[]   = "ServerNotice\tOK\tSrc\t%d\tCode\t%d\tUser\t%d\tLv\t%d\tPct\t%d";

    // ── диагностика ветки заточки (по просьбе после живого теста) ───────────
    // Пишется на КАЖДУЮ попытку улучшения, чтобы было видно, доходит ли до нас
    // управление на неудачной попытке и почему не сработал анонс провала.
    const char kFmtRefIn[]   = "Refine\tIN\tUser\t%d\tOk\t%d\tCode\t%d\tPlate\t%d\tSlot\t%d\tLv\t%d\tPct\t%d"
                               "\tPreLv\t%d\tPrePct\t%d\tPreValid\t%d";
    const char kFmtRefArm[]  = "Refine\tARM\tUser\t%d\tCode\t%d\tPlate\t%d\tSlot\t%d\tLv\t%d";
    const char kFmtRefSkip[] = "Refine\tSKIP\tUser\t%d\tOk\t%d\tReason\t%s";
    const char kFmtRefKey[]  = "Refine\tKEYMISS\tUser\t%d\tarm(code %d plate %d slot %d armed %d) "
                               "vs cur(code %d plate %d slot %d)";
    // ── диагностика снимка «ДО броска» (площадка 0x4FFFC5) ──────────────────
    const char kFmtRefPre[]  = "Refine\tPRE\tUser\t%d\tCode\t%d\tPlate\t%d\tSlot\t%d\tLv\t%d\tPct\t%d";
    const char kFmtRefPreMiss[] = "Refine\tPREMISS\tUser\t%d\tpre(code %d plate %d slot %d valid %d age %u мс) "
                                  "vs cur(code %d plate %d slot %d)";

    // теги источника в теле пакета
    enum { SRC_PICK = 1, SRC_GACHA = 2, SRC_PGACHA = 3, SRC_REFINE_OK = 4, SRC_REFINE_FAIL = 5 };
    // причины отказа для лога
    enum { SKIP_BADCODE = 1, SKIP_NOTRARE = 2, SKIP_NOUSER = 3, SKIP_NOTABLE = 4 };

    // ── настройки (читаются один раз при старте) ────────────────────────────
    bool g_pickup = false, g_gacha = false, g_pgacha = false;
    bool g_refine = false, g_refineFail = false;
    bool g_failNeedsPriorSuccess = true;   // 1 = красная строка только после зелёной
    int  g_thresholdLevel = 6;      // порог по item+24 (ступень)
    int  g_thresholdPct   = 0;      // доп. порог по item+27, 0 = не учитывать
    int  g_scope = 0;               // 0 = весь сервер, 1 = сектор
    int  g_failWindowSec = 600;

    // ── таблица «анонсируемых» кодов (грейд >= 3 и подходящий тип) ──────────
    struct Range { int lo, hi; };
    Range g_ranges[1024];
    int   g_rangeCount = 0;

    bool IsRare(int code)
    {
        // таблица отсортирована по возрастанию — обычный двоичный поиск
        int a = 0, b = g_rangeCount - 1;
        while (a <= b)
        {
            const int m = (a + b) / 2;
            if (code < g_ranges[m].lo)      { b = m - 1; }
            else if (code > g_ranges[m].hi) { a = m + 1; }
            else                            { return true; }
        }
        return false;
    }

    // Файл: строки вида "20679" или "61785-61790"; '#' и ';' — комментарий.
    int LoadGradeTable(const wchar_t* baseDir, const wchar_t* rel)
    {
        wchar_t path[MAX_PATH];
        wsprintfW(path, L"%s%s", baseDir, rel);
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
        {
            Log::Line(L"    P11: ! таблица кодов не найдена: %s", path);
            return 0;
        }
        const DWORD size = GetFileSize(h, nullptr);
        char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, size + 1);
        if (!buf) { CloseHandle(h); return 0; }
        DWORD got = 0;
        ReadFile(h, buf, size, &got, nullptr);
        buf[got] = 0;
        CloseHandle(h);

        g_rangeCount = 0;
        char* p = buf;
        while (*p && g_rangeCount < ARRAYSIZE(g_ranges))
        {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') { ++p; }
            if (!*p) { break; }
            if (*p == '#' || *p == ';')
            {
                while (*p && *p != '\n') { ++p; }
                continue;
            }
            const int lo = atoi(p);
            while (*p && *p != '-' && *p != '\r' && *p != '\n') { ++p; }
            const int hi = (*p == '-') ? atoi(p + 1) : lo;
            while (*p && *p != '\n') { ++p; }
            if (lo > 0 && hi >= lo)
            {
                g_ranges[g_rangeCount].lo = lo;
                g_ranges[g_rangeCount].hi = hi;
                ++g_rangeCount;
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
        Log::Line(L"    P11: таблица кодов загружена: %s, диапазонов %d", path, g_rangeCount);
        return g_rangeCount;
    }

    // ── состояние «взведён анонс успеха» для анонса неудачи ─────────────────
    // Ключ — userNum + имя персонажа + код + plate + слот: уникального id
    // экземпляра предмета в 57-байтовой записи НЕТ (проверено), а один только
    // userNum после выхода игрока переиспользуется другим.
    struct Arm
    {
        char  name[20];
        int   code;
        BYTE  plate;
        short slot;
        DWORD tick;
        bool  armed;
    };
    Arm g_arm[0x226] = {};      // та же граница, что у серверной sub_5328F0

    // ── снимок «ступень/процент ДО броска» (площадка 0x4FFFC5) ──────────────
    // Ключ — тот же userIdx (word [ebp+8]); проверка попадания — code/plate/slot
    // и окно времени. Массив статический: в DllMain и в трамплине аллокаций нет.
    struct Pre
    {
        int   code;
        BYTE  plate;
        short slot;
        int   level;    // item+24 ДО броска
        int   pct;      // item+27 ДО броска
        DWORD tick;
        bool  valid;
    };
    Pre g_pre[0x226] = {};

    // ── общая отправка анонса ───────────────────────────────────────────────
    void Announce(void* mgr, int itemCode, int userNum, int src,
                  bool needGrade, int level, int pct, bool isFail)
    {
        SrvLog(Srv::kLogCatItem, kFmtIn, src, itemCode, userNum, level, pct);

        // код должен принадлежать ОДНОЙ ИЗ ДВУХ таблиц — так же, как в P01 (см. коммент выше)
        if (!SrvIsItemCode(itemCode) && !SrvIsSowelCode(itemCode))
        {
            SrvLog(Srv::kLogCatItem, kFmtSkip, src, itemCode, userNum, SKIP_BADCODE);
            return;
        }
        if (needGrade)
        {
            if (g_rangeCount == 0)
            {
                SrvLog(Srv::kLogCatItem, kFmtSkip, src, itemCode, userNum, SKIP_NOTABLE);
                return;
            }
            if (!IsRare(itemCode))
            {
                SrvLog(Srv::kLogCatItem, kFmtSkip, src, itemCode, userNum, SKIP_NOTRARE);
                return;
            }
        }
        BYTE* user = SrvGetUser(mgr, (short)userNum);
        if (!user)
        {
            SrvLog(Srv::kLogCatItem, kFmtSkip, src, itemCode, userNum, SKIP_NOUSER);
            return;
        }

        BYTE body[Srv::kNoticeLen];
        memset(body, 0, sizeof(body));
        *(int*)body = itemCode;
        memcpy(body + 4, user + Srv::kOffCharName, 20);
        body[24] = (BYTE)src;
        body[25] = (BYTE)level;
        *(WORD*)(body + 26) = (WORD)pct;
        body[28] = isFail ? 1 : 0;

        if (g_scope == 1)
        {
            SrvSendSector(mgr, (short)userNum, (short)Srv::kOpItemAcquired,
                          (short)Srv::kNoticeLen, body, 1);
        }
        else
        {
            SrvSendAllInMap(mgr, (short)Srv::kOpItemAcquired,
                            (short)Srv::kNoticeLen, body, 1);
        }
        SrvLog(Srv::kLogCatItem, kFmtOk, src, itemCode, userNum, level, pct);
    }

    bool SameItem(const Arm& a, const char* name, int code, BYTE plate, short slot)
    {
        return a.armed && a.code == code && a.plate == plate && a.slot == slot
            && memcmp(a.name, name, sizeof(a.name)) == 0;
    }
}

// ═══════════════════════ обработчики (зовутся трамплинами) ═══════════════════
extern "C" {

void __stdcall AsdaOnPickup(void* mgr, int userNum, BYTE* itemRec)
{
    P59_OnPickup(mgr, userNum, *(int*)itemRec);   // ★ A6: журнал подбора редкого (сам проверяет Enabled/Pickup)
    if (!g_pickup) { return; }
    Announce(mgr, *(int*)itemRec, userNum, SRC_PICK, true, 0, 0, false);
}

void __stdcall AsdaOnGacha(void* mgr, int userNum, int code)
{
    if (!g_gacha) { return; }
    Announce(mgr, code, userNum, SRC_GACHA, true, 0, 0, false);
}

void __stdcall AsdaOnPremiumGacha(void* mgr, int userNum, int code)
{
    if (!g_pgacha) { return; }
    Announce(mgr, code, userNum, SRC_PGACHA, true, 0, 0, false);
}

// ★ ВХОД ВЕТКИ НЕУДАЧИ (0x4FFFC5) — снимок ступени/процента ДО броска.
//   Вызывается ДО того, как сервер обнулит item+24/item+27, поэтому именно здесь
//   видно то, что игрок теряет. level = item+24, pct = item+27.
void __stdcall AsdaOnRefinePre(int userNum, BYTE* itemRec, int level, int pct)
{
    if (!g_refine || !g_refineFail) { return; }
    if ((unsigned)userNum >= ARRAYSIZE(g_pre)) { return; }

    Pre& p  = g_pre[userNum];
    p.code  = *(int*)itemRec;
    p.plate = itemRec[4];
    p.slot  = *(short*)(itemRec + 5);
    p.level = level;
    p.pct   = pct;
    p.tick  = GetTickCount();
    p.valid = true;

    SrvLog(Srv::kLogCatItem, kFmtRefPre, userNum, p.code, (int)p.plate, (int)p.slot, level, pct);
}

// ok — заточка удалась; level = item+24 (ступень); pct = item+27 (проценты)
void __stdcall AsdaOnRefine(void* mgr, int userNum, BYTE* itemRec, int ok, int level, int pct)
{
    if (!g_refine) { return; }
    if ((unsigned)userNum >= ARRAYSIZE(g_arm)) { return; }

    const int   code  = *(int*)itemRec;
    const BYTE  plate = itemRec[4];
    const short slot  = *(short*)(itemRec + 5);
    Arm& a = g_arm[userNum];
    Pre& p = g_pre[userNum];

    // ★ строка пишется на КАЖДУЮ попытку — сразу видно, доходит ли до нас
    //   управление на неудачной попытке (было неочевидно после живого теста).
    //   Печатаем и снимок, чтобы «до/после» было видно в одной строке.
    SrvLog(Srv::kLogCatItem, kFmtRefIn, userNum, ok, code, (int)plate, (int)slot, level, pct,
           p.level, p.pct, (int)p.valid);

    BYTE* user = SrvGetUser(mgr, (short)userNum);
    if (!user)
    {
        SrvLog(Srv::kLogCatItem, kFmtRefSkip, userNum, ok, "CUser не найден");
        return;
    }
    const char* name = (const char*)(user + Srv::kOffCharName);

    if (ok)
    {
        // ★ УСПЕХ идёт по СТОКОВОМУ пути: снимок сюда не примешивается — в кадре
        //   уже лежат НОВЫЕ ступень/процент, и анонсировать надо именно их.
        //   Снимок гасим: он мог остаться от давней неудачи, которая до хука не
        //   дошла (путь 0x5000B2 -> 0x5000BE -> лог + 6505 + выход).
        p.valid = false;

        // порог считаем ПО СТУПЕНИ; доп. порог по проценту — если задан
        if (level < g_thresholdLevel)
        {
            SrvLog(Srv::kLogCatItem, kFmtRefSkip, userNum, ok, "ступень ниже порога");
            return;
        }
        if (g_thresholdPct > 0 && pct < g_thresholdPct)
        {
            SrvLog(Srv::kLogCatItem, kFmtRefSkip, userNum, ok, "процент ниже доп. порога");
            return;
        }

        Announce(mgr, code, userNum, SRC_REFINE_OK, false, level, pct, false);

        // взвести анонс неудачи для ЭТОГО ЖЕ предмета
        memcpy(a.name, name, sizeof(a.name));
        a.code  = code;
        a.plate = plate;
        a.slot  = slot;
        a.tick  = GetTickCount();
        a.armed = g_refineFail;
        SrvLog(Srv::kLogCatItem, kFmtRefArm, userNum, code, (int)plate, (int)slot, level);
        return;
    }

    // ── НЕУДАЧА ─────────────────────────────────────────────────────────────
    if (!g_refineFail)
    {
        SrvLog(Srv::kLogCatItem, kFmtRefSkip, userNum, ok, "RefineFailEnabled=0");
        return;
    }

    // ★★★ Значения ДО броска. К этому месту сервер уже мог обнулить item+24/+27
    //     (0x500009/0x500010 и 0x500080/0x500087), поэтому level/pct из кадра тут
    //     недостоверны. Берём снимок, сделанный трамплином на входе ветки неудачи.
    //     Снимок считается годным, только если совпадает ключ предмета и он свежий.
    int         preLevel = level;
    int         prePct   = pct;
    const DWORD preAge   = GetTickCount() - p.tick;
    if (p.valid && p.code == code && p.plate == plate && p.slot == slot
        && preAge <= (DWORD)g_failWindowSec * 1000u)
    {
        preLevel = p.level;
        prePct   = p.pct;
    }
    else
    {
        // не должно случаться (ok==0 достижимо только через площадку снимка),
        // но если случилось — работаем на том, что прочитано в кадре, и пишем это в лог
        SrvLog(Srv::kLogCatItem, kFmtRefPreMiss, userNum,
               p.code, (int)p.plate, (int)p.slot, (int)p.valid, preAge,
               code, (int)plate, (int)slot);
    }
    p.valid = false;                            // снимок одноразовый

    if (g_failNeedsPriorSuccess)
    {
        // штатный режим: красная строка только после зелёного анонса ТОГО ЖЕ предмета
        if (!SameItem(a, name, code, plate, slot))
        {
            SrvLog(Srv::kLogCatItem, kFmtRefKey, userNum,
                   a.code, (int)a.plate, (int)a.slot, (int)a.armed, code, (int)plate, (int)slot);
            return;
        }
        if ((GetTickCount() - a.tick) > (DWORD)g_failWindowSec * 1000u)
        {
            a.armed = false;
            SrvLog(Srv::kLogCatItem, kFmtRefSkip, userNum, ok, "окно RefineFailWindowSec истекло");
            return;
        }
    }
    else
    {
        // режим «без предварительного успеха»: достаточно, чтобы предмет уже был
        // на ступени >= порога (именно этого ждали на живом тесте).
        // ★ порог считаем по ступени ДО броска — после броска там может быть 0.
        if (preLevel < g_thresholdLevel)
        {
            SrvLog(Srv::kLogCatItem, kFmtRefSkip, userNum, ok, "ступень ниже порога");
            return;
        }
    }

    // в тело 6131 кладём то, что игрок ПОТЕРЯЛ, а не обнулённые значения
    Announce(mgr, code, userNum, SRC_REFINE_FAIL, false, preLevel, prePct, true);
    a.armed = false;                            // одна красная строка на один зелёный
}

}   // extern "C"

// ═══════════════════════════ трамплины ══════════════════════════════════════
namespace
{
    DWORD g_pPickRet   = Srv::Hooks::kPickEpilogue  + 5;    // 0x4D5E66
    DWORD g_pGachaRet  = 0x004F5666;                        // цель оригинального `jmp`
    DWORD g_pPGachaRet = Srv::Hooks::kPGachaSuccess + 5;    // 0x4F7673
    DWORD g_pRefineRet = Srv::Hooks::kRefineSuccess + 7;    // 0x500609
    DWORD g_pRefPreRet = Srv::Hooks::kRefineFailEntry + 7;  // 0x4FFFCC

    const BYTE kOrigPick[5]   = { 0x8B, 0x4D, 0xF4, 0x33, 0xCD };
    const BYTE kOrigGacha[5]  = { 0x83, 0xC4, 0x1C, 0xEB, 0x2A };
    const BYTE kOrigPGacha[5] = { 0xB9, 0x38, 0x05, 0x7E, 0x00 };
    const BYTE kOrigRefine[7] = { 0x0F, 0xB6, 0x8D, 0xEE, 0xFE, 0xFF, 0xFF };
    const BYTE kOrigRefPre[7] = { 0xC6, 0x85, 0x38, 0xFE, 0xFF, 0xFF, 0x08 };

    __declspec(naked) void PickTrampoline()
    {
        __asm
        {
            pushad
            cmp  byte ptr [ebp-0x0B4], 1        // v71 == 1 -> успешный подбор
            jne  pick_done
            lea  eax, [ebp-0x560]               // 60-байтовая запись предмета
            push eax
            movsx ecx, word ptr [ebp+8]
            push ecx
            mov  eax, dword ptr [ebp-0x5F0]     // CUserManager
            push eax
            call AsdaOnPickup
        pick_done:
            popad
            mov  ecx, dword ptr [ebp-0x0C]      // оригинал: проверка /GS-куки
            xor  ecx, ebp
            jmp  dword ptr [g_pPickRet]
        }
    }

    __declspec(naked) void GachaTrampoline()
    {
        __asm
        {
            add  esp, 0x1C                      // оригинал: снятие аргументов лог-вызова
            pushad
            mov  eax, dword ptr [ebp-0x0D4]     // код ВЫИГРЫША (не коробки!)
            push eax
            movsx ecx, word ptr [ebp+8]
            push ecx
            mov  eax, dword ptr [ebp-0x194]
            push eax
            call AsdaOnGacha
            popad
            jmp  dword ptr [g_pGachaRet]
        }
    }

    __declspec(naked) void PremiumGachaTrampoline()
    {
        __asm
        {
            pushad                              // аргументы DB-вызова уже на стеке
            mov  eax, dword ptr [ebp-0x0D9]
            push eax
            movsx ecx, word ptr [ebp+8]
            push ecx
            mov  eax, dword ptr [ebp-0x160]
            push eax
            call AsdaOnPremiumGacha
            popad
            mov  ecx, 0x007E0538                // оригинал
            jmp  dword ptr [g_pPGachaRet]
        }
    }

    __declspec(naked) void RefineTrampoline()
    {
        __asm
        {
            pushad
            movzx eax, word ptr [ebp-0x205]     // item+27 — ПРОЦЕНТ
            push eax
            movzx eax, byte ptr [ebp-0x208]     // item+24 — ступень
            push eax
            movzx eax, byte ptr [ebp-0x112]     // успех заточки
            push eax
            lea  eax, [ebp-0x220]               // запись предмета
            push eax
            movsx ecx, word ptr [ebp+8]
            push ecx
            mov  eax, dword ptr [ebp-0x2EC]
            push eax
            call AsdaOnRefine
            popad
            movzx ecx, byte ptr [ebp-0x112]     // оригинал
            jmp  dword ptr [g_pRefineRet]
        }
    }

    // ★ вход ветки НЕУДАЧИ (0x4FFFC5): снимок ДО обнуления ступени/процента.
    //   Кадр функции цел, ebp наш. pushfd — потому что дальше по ветке идёт
    //   `movzx/add/mov`, а сразу за ними `cmp`; флаги не нужны, но сохраняем
    //   их явно, чтобы вытесненная инструкция вела себя один-в-один со стоком.
    __declspec(naked) void RefineFailPreTrampoline()
    {
        __asm
        {
            pushad
            pushfd
            movzx eax, word ptr [ebp-0x205]     // item+27 — ПРОЦЕНТ до броска
            push eax
            movzx eax, byte ptr [ebp-0x208]     // item+24 — ступень до броска
            push eax
            lea  eax, [ebp-0x220]               // запись предмета (код/plate/слот)
            push eax
            movsx ecx, word ptr [ebp+8]
            push ecx
            call AsdaOnRefinePre
            popfd
            popad
            mov  byte ptr [ebp-0x1C8], 8        // вытесненная инструкция оригинала
            jmp  dword ptr [g_pRefPreRet]
        }
    }
}

// ★ A6: общие точки таблицы «редких» кодов (P59). Таблица одна на DLL; грузится один раз.
bool P11_IsRareCode(int code) { return g_rangeCount > 0 && IsRare(code); }
int  P11_EnsureGradeTable()
{
    if (g_rangeCount > 0) { return g_rangeCount; }
    wchar_t rel[MAX_PATH];
    Config::GetStr(L"P11_ServerAnnounceSources", L"GradeTableFile", L"ConfigSet\\announce_codes.txt", rel, ARRAYSIZE(rel));
    if (rel[0]) { LoadGradeTable(Config::BaseDir(), rel); }
    return g_rangeCount;
}

PatchResult P11_ServerAnnounceSources()
{
    const wchar_t* S = L"P11_ServerAnnounceSources";
    g_pickup = Config::GetBool(S, L"PickupEnabled", true);
    g_gacha  = Config::GetBool(S, L"GachaEnabled", true);
    g_pgacha = Config::GetBool(S, L"PremiumGachaEnabled", true);
    g_refine = Config::GetBool(S, L"RefineEnabled", true);
    g_refineFail     = Config::GetBool(S, L"RefineFailEnabled", true);
    g_failNeedsPriorSuccess = Config::GetBool(S, L"RefineFailRequiresPriorSuccess", true);
    g_thresholdLevel = Config::GetInt(S, L"RefineThresholdLevel", 6);
    g_thresholdPct   = Config::GetInt(S, L"RefineThresholdPercent", 0);
    g_scope          = Config::GetInt(S, L"Scope", 0);
    g_failWindowSec  = Config::GetInt(S, L"RefineFailWindowSec", 600);

    // ★ A6: трамплин подбора нужен и P59 (журнал редкого подбора) — ставим его и при PickupEnabled=0.
    const bool pickHook = g_pickup || P59_PickupWanted();
    if (!pickHook && !g_gacha && !g_pgacha && !g_refine) { return PatchResult::Disabled; }

    // таблица грейдов нужна только трём «редким» источникам
    if (g_pickup || g_gacha || g_pgacha)
    {
        P11_EnsureGradeTable();
        if (g_rangeCount == 0)
        {
            Log::Line(L"    P11: ! таблица кодов пуста — источники подбор/гача/премиум-гача "
                      L"НЕ будут анонсировать (защита от спама)");
        }
    }

    // Пятая площадка нужна только когда анонсируем НЕУДАЧУ заточки.
    const bool wantPre = g_refine && g_refineFail;

    const Site sites[] = {
        { Srv::Hooks::kPickEpilogue,   kOrigPick,   sizeof(kOrigPick)   },
        { Srv::Hooks::kGachaSuccess,   kOrigGacha,  sizeof(kOrigGacha)  },
        { Srv::Hooks::kPGachaSuccess,  kOrigPGacha, sizeof(kOrigPGacha) },
        { Srv::Hooks::kRefineSuccess,  kOrigRefine, sizeof(kOrigRefine) },
        { Srv::Hooks::kRefineFailEntry, kOrigRefPre, sizeof(kOrigRefPre) },
    };
    const int siteCount = wantPre ? ARRAYSIZE(sites) : ARRAYSIZE(sites) - 1;
    if (!VerifyAllSites(L"P11", sites, siteCount)) { return PatchResult::Mismatch; }

    bool ok = true;
    if (pickHook) { ok &= Hook::WriteJmp(Srv::Hooks::kPickEpilogue,  &PickTrampoline,         sizeof(kOrigPick)); }
    if (g_gacha)  { ok &= Hook::WriteJmp(Srv::Hooks::kGachaSuccess,  &GachaTrampoline,        sizeof(kOrigGacha)); }
    if (g_pgacha) { ok &= Hook::WriteJmp(Srv::Hooks::kPGachaSuccess, &PremiumGachaTrampoline, sizeof(kOrigPGacha)); }
    if (g_refine) { ok &= Hook::WriteJmp(Srv::Hooks::kRefineSuccess, &RefineTrampoline,       sizeof(kOrigRefine)); }
    // ★ снимок «ДО броска» — ставится ПОСЛЕ основного хука заточки: сам по себе
    //   он ничего не анонсирует, только заполняет g_pre[].
    if (wantPre)  { ok &= Hook::WriteJmp(Srv::Hooks::kRefineFailEntry, &RefineFailPreTrampoline, sizeof(kOrigRefPre)); }
    if (!ok) { return PatchResult::Failed; }

    Log::Line(L"    P11: подбор=%d гача=%d премиум=%d заточка=%d (порог ступень>=%d, "
              L"доп.порог %%>=%d, неудачи=%d нужен-успех=%d окно %d с), зона=%s (%s)",
              g_pickup, g_gacha, g_pgacha, g_refine, g_thresholdLevel, g_thresholdPct,
              g_refineFail, g_failNeedsPriorSuccess, g_failWindowSec,
              g_scope == 1 ? L"сектор" : L"ВЕСЬ СЕРВЕР",
              g_scope == 1 ? L"sub_52E630" : L"SendPacket_AllPlayer_InMap@0x52E520 — цикл по всем 550 слотам");
    Log::Line(L"    P11: снимок ступени/процента ДО броска (0x%08X) — %s",
              Srv::Hooks::kRefineFailEntry,
              wantPre ? L"ПОСТАВЛЕН: анонс неудачи покажет то, что игрок потерял"
                      : L"не нужен (анонс неудачи выключен)");
    return PatchResult::Applied;
}
