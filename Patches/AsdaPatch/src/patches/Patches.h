// Copyright (c) 2026 @sitxovski (Discord)
// Patches.h — реестр патчей. Каждый патч живёт в своём .cpp и регистрируется здесь.
#pragma once
#include <windows.h>

// Результат установки одного патча.
enum class PatchResult
{
    Applied,        // поставлен
    Disabled,       // выключен в ini
    Mismatch,       // оригинальные байты не совпали — НЕ поставлен
    Failed          // ошибка записи/доступа — НЕ поставлен
};

struct PatchEntry
{
    const wchar_t* section;     // секция в patches.ini
    const wchar_t* title;       // краткое описание для лога
    PatchResult  (*apply)();    // сам патч: читает ini, сверяет байты, пишет
    // ★ Для каких образов патч предназначен: имена exe через ';', в нижнем регистре.
    //   nullptr = только GameServer.exe (так было, пока DLL жила в нём одном).
    //   Нужно с тех пор, как DLL инъектируется ещё и в процессы работы с базой:
    //   иначе патчи GameServer пытались бы лечь в чужой образ и давали MISMATCH.
    const wchar_t* hosts;
};

extern const PatchEntry* g_patches;
extern const int         g_patchCount;

// ── реализации патчей ───────────────────────────────────────────────────────
PatchResult P01_RareItemNotice6616();
PatchResult P02_GmNotice6030();
PatchResult P03_OperatorSkillPointLog();
PatchResult P04_InvincibleGmGate();
PatchResult P05_PrimiumGachaExtraSend();
PatchResult P06_Db2601Send();
PatchResult P07_Sub43C690EarlyExit();
PatchResult P08_FunctionItemUseCheckOff();
PatchResult P11_ServerAnnounceSources();
PatchResult P12_DefaultServerIp();
PatchResult P13_ChatWideChannels6560();
PatchResult P14_ChatMessageLength();
PatchResult P15_FunctionItemCodeBounds();
PatchResult P16_GachaPrizeToInven();
PatchResult P17_SqlCodePage();
PatchResult P18_WarehouseDupeAndBounds();
PatchResult P19_AuctionRecordBounds();
PatchResult P20_PartyInviteValidation();
PatchResult P21_TitleMask512();
PatchResult P24_FameRatingRevoke();
PatchResult P25_GmRatingRecalc();
PatchResult P27_SoulmateServerDefects();
PatchResult P29_LevelCap();                 // потолок уровня игрока 59 → MaxLevel (2026-09-11)
PatchResult P30_MapSlots();                 // число слотов карт 23 → MaxMaps (2026-09-12)
PatchResult P33_GearUpgradeServerDefects(); // заточка 6504/6505: дефекты волны 6 (2026-09-25)
PatchResult P34_NecklaceFixedOptions();     // фикс. опции ожерелий 4/61 (2026-09-25)
PatchResult P35_CraftServerDefects();       // ремесло 6598/6600/6602/6604: оборонительные правки (2026-09-25)
PatchResult P36_CraftSuccessOption();       // опция 24 «Успешное изготовление %» в лестницу ремесла (2026-09-26)
PatchResult P32_PetWrongOpcode6101();       // питомцы: отказ по charId 6101 -> 6103/6109 (2026-09-27)
PatchResult P31_PetUnionRemoveNotify();     // юнион питомцев: 6111 на каждый съеденный материал (2026-09-27)
PatchResult P40_CrystalTeleportGate();      // телепорт кристаллом 5477: «у NPC» + «карта открыта» (2026-09-27)
PatchResult P41_GmHide4056();               // скрытый оператор: 4056 соседям не уходит (2026-09-27)
PatchResult P42_GmHideTarget();             // скрытый оператор — недопустимая цель боя игроков (2026-09-27)
PatchResult P38_ClanSlotCap();              // лимит мест клана: проверка сверяет прибавку +10 (2026-09-27)
PatchResult P43_StorePriceCap();            // потолок цены личной лавки 100млн->1млрд + защита переполнения (2026-09-27)
PatchResult P44_ExchangeIntegrity();        // обмен/лавка: замок завершения, границы окна/лота, сброс при смерти (2026-09-29)
PatchResult P46_StoreShoutOverflow();       // крик лавки 6316: зажим длины копии ДО memcpy (переполнение стека) (2026-10-08)
PatchResult P47_IdentityOperatorGate();     // античит А0: GM-флаг операторских опкодов, сверка 20000↔логон, IP в DB-логон (2026-10-12)
PatchResult P48_KickAutoBlock();            // античит А0: автоблок (UPHackBlock) после N киков в мире (2026-10-12)
PatchResult P49_OriginalChecksRestore();    // античит А0: кик за повторы (sub_524440) + MD5 5450 по 0x101 (2026-10-12)
PatchResult P53_AcJournal();                // античит acdb: журнал в БД (joylog1.ac) + зеркало штатных проверок (2026-10-12)
PatchResult P54_BlockedLoginMessage();      // античит acdb: отказ P50 по блоку -> 4101 код 7 «учётная запись заблокирована» (2026-10-12)
PatchResult P56_CombatLimits();             // античит В5 (мера 9): лимиты боя GameServer — повторы целей, заявка «в пути», пол частоты, дальность по клеткам (2026-10-12)
PatchResult P57_MoveGuard();                // античит A6: порог Hack Position -> кик; пределы 4006; 4008 из проверенных полей (2026-10-12)
PatchResult P58_DisconnectReasonLog();      // античит A6 (П1): причина отключения 4101 в общий лог всегда (2026-10-12)
PatchResult P59_RareDropJournal();          // античит A6 (П4): журнал редкого дропа с монстров и подбора (2026-10-12)
PatchResult P61_TrafficEncryption();        // шифрование трафика: прослойка AsdaSecure (ECDH+ECDSA+AES-256-GCM), Enabled=0 (2026-10-12)
PatchResult P65_ConsumableType();           // античит A7 (L5/A9): тип расходника по Function_Table — 6551/6553/5433 + код пакета==слот 5450 (2026-10-12)

// ── ОБЩИЕ ТОЧКИ волны A6 (P57/P59, 2026-10-12) ───────────────────────────────
//   P53 зовёт P57 на своих площадках «CharMove/CharReMove Hack Position» (kind 1/2, mgr = CUserManager,
//   user = CUser); если P53 площадок не ставил — P57 ставит на те же вызовы свои стабы и зовёт себя сам.
extern "C" void __stdcall P57_OnHackPosition(int kind, void* mgr, BYTE* user);
//   Таблица «редких» кодов P11 (announce_codes.txt, грейд >= 3) — общая для P01/P11/P59.
bool P11_IsRareCode(int code);          // код в таблице (двоичный поиск); false при пустой таблице
int  P11_EnsureGradeTable();            // загрузить таблицу, если ещё не загружена; вернуть число диапазонов
//   Подбор редкого (P11 AsdaOnPickup → P59): трамплин P11 ставится и ради P59.
bool P59_PickupWanted();
void P59_OnPickup(void* mgr, int userNum, int itemCode);

PatchResult P55_PacketValidator();          // античит В4: общий валидатор пакетов — длина кадра по опкоду + частота по классу (2026-10-12)
PatchResult P60_ValueGuard();               // античит A7 (L5, A3/A4): значения по серверным таблицам — 5020 количество/сумма, 6180/6150 знак, 5048 код книги, 5041 номер награды, 6586 анти-повтор/знак, 6521 ступень (2026-10-12)
PatchResult P62_SlotUniqueness();           // античит A7 (L3/A5): уникальность пар (контейнер, слот)/uid в 5018/6549/6506/6555/6096/6112, слот 0 ≠ слот 1 в 6067 (2026-10-12)
PatchResult P63_InFlightLock();             // античит A7 (L2): общий замок «запрос в БД в полёте» — 25 семей, постановка у sub_5646C0, снятие в диспетчере ответов БД (2026-10-12)
// ── ОБЩАЯ ТОЧКА P62 ↔ P63 (integ2, 2026-10-12) ─────────────────────────────
//   Оба перехватывают ОДИН И ТОТ ЖЕ `call sub_5646C0` (E8 rel32) в пяти обработчиках: 6096 @0x55AE4F,
//   6506 @0x501A5C, 6549 @0x535202, 6555 @0x5376F3, 6112 @0x4590C7. Порядок в рантайме фиксирован:
//   P62 (уникальность) → P63 (замок «в полёте») → sub_5646C0. Замок ставится только тогда, когда запрос реально
//   уходит в БД: отказ P62 (Mode=1) идёт в стоковое тело отказа, до P63 управление не доходит.
//   Механизм: у стаба P62 на каждой площадке есть слот «следующий вызов» (по умолчанию sub_5646C0); на проходе стаб
//   уходит в него ХВОСТОВЫМ jmp — стек, регистры (ecx = this, ebp = кадр обработчика) и адрес возврата те же, что у
//   стоковой call, поэтому стаб P63 видит ровно стоковый вход.
//   Установка в любом порядке: P63 видит на площадке rel32 → стаб P62 ЭТОЙ площадки (P62_SendStubAt) — байты не
//   пишет, исходные сверяет по таблице P62 (P62_SendOrigAt), подставляет свой стаб в слот (P62_ChainSend).
//   P62 видит rel32 → St_Send P63 (P63_SendStubAt) — забирает площадку себе, слот := St_Send P63.
//   Выключен любой из двух — второй ставит площадку сам по стоковым байтам.
const void* P62_SendStubAt(DWORD va);                 // стаб P62, если P62 поставил площадку va; иначе nullptr
const BYTE* P62_SendOrigAt(DWORD va);                 // исходные 5 байт площадки va по таблице P62 (nullptr — не площадка P62)
bool        P62_ChainSend(DWORD va, const void* next);// подставить «следующий вызов» на площадке va; false — площадка не P62
const void* P63_SendStubAt(DWORD va);                 // St_Send, если P63 сам записал площадку va; иначе nullptr
const BYTE* P63_SendOrigAt(DWORD va);                 // исходные 5 байт площадки va по таблице P63 (nullptr — не площадка P63)
// Экспорт для стендов: цель «следующего вызова» стаба P62 на площадке va (0 — площадка не поставлена P62).
extern "C" __declspec(dllexport) DWORD __stdcall P62_GetSendNext(DWORD va);

// Статистика P63 (экспорт P63_GetStats — для стенда tools/stand_p63).
struct P63_Stats
{
    LONG locksSet;          // замков поставлено
    LONG released;          // снято ответом БД
    LONG dupJournal;        // дублей в полёте (Mode=0, пропущены)
    LONG dupEarly;          // дублей отклонено ранней веткой «занят» (Mode=1)
    LONG dupSuppressed;     // повторных отправок в БД подавлено (Mode=1)
    LONG lateReply;         // ответов БД после тайм-аута
    LONG staleReply;        // ответов для другой учётки в слоте
    LONG expired;           // просроченных/чужих замков перезаписано новой постановкой
    LONG cleared;           // замков сброшено при выходе сессии
    LONG badMgr;            // менеджер не прошёл самопроверку (CUser+0x0C != слот)
    LONG journaled;         // строк журнала после ограничителя
    LONG journalSuppressed; // подавлено ограничителем
};

// ── ОБЩИЕ ТОЧКИ P55 ↔ P47 (В4) ─────────────────────────────────────────────
//   Гейт P55 зовётся из P47_OperatorGate (стаб 0x42AB4F) первым, с теми же аргументами.
//   P55_GateWanted — P47 ставит стаб и при OperatorGmFlag=0, если P55 включён (читает ini сам:
//   P55 в реестре ПОСЛЕ P47/P53). P55_PacketGate: 1 — пропустить, 0 — обработчик не вызывать (Mode=1).
bool P55_GateWanted();
int  P55_PacketGate(void* mgr, int opcode, int userNum, const BYTE* pkt);
// Статистика P55 (экспорт P55_GetStats/P55_ResetState — для стенда tools/stand_p55).
struct P55_Stats
{
    LONG checked;       // пакетов через гейт
    LONG hdrShort;      // кадр короче 10 б
    LONG lenShort;      // кадр короче minSize
    LONG lenLong;       // кадр длиннее maxSize
    LONG rate;          // превышение частоты класса
    LONG noLen;         // опкод без записи в таблице длин (не проверялся)
    LONG refused;       // отказов (Mode=1)
    LONG hackCounted;   // +1 к Hack Packet
    LONG journaled;     // строк журнала/лога (после ограничителя)
    LONG suppressed;    // подавлено ограничителем
};
// ★ sec2 (решение владельца 14.10: за поддельный/битый пакет — только ступени P69): доля нарушений P55 1/2/4 в штатных счётчиках
//   кика CheckDisConnectUser (Secret +0x04, MD5 +0x08, NotKnow +0x1E, Hack +0x22). P55_KickAttribution — P48 на входе
//   Send_DisConnectType: which 0..3 — счётчик кика тип 3 (−1 — другой кик, только сброс учёта), pre — Secret до сброса стабом P49
//   (−1 — читать CUser); true — кик вызван нарушениями P55 (без них база + прочее ≤ порога) — P48 не считает; *otherOut = база +
//   прочее. ★ sec2c: P55_PendOtherHack — P47 ПЕРЕД своим +1 к Hack (отказ, не нарушение P55) объявляет его «прочим» под замком
//   учёта; P55_CancelOtherHack — +1 не случился (SEH). Экспорт P55_GetKickStats / P55_TestKickAttr — стенд.
bool P55_KickAttribution(const BYTE* user, int userNum, int which, int pre, int* integOut, int* otherOut);
void P55_PendOtherHack(int userNum);
void P55_CancelOtherHack(int userNum);
struct P55_KickStats
{
    LONG integrityOnly; // кик тип 3 вызван только нарушениями P55 1/2/4 (P48 не считает)
    LONG counted;       // кик тип 3 по прочим причинам (P48 считает как раньше)
};

PatchResult P64_StatePreamble();            // античит A7 (L4/A8): общая преамбула состояния персонажа — мёртв/занят/душа/одержим/не в игре (2026-10-12)

// ── ОБЩИЕ ТОЧКИ P64 ↔ P47 (A7) ─────────────────────────────────────────────
//   Гейт P64 зовётся из P47_OperatorGate (стаб 0x42AB4F) ВТОРЫМ — сразу после P55, с теми же аргументами.
//   P64_GateWanted — P47 ставит стаб и при OperatorGmFlag=0, если P64 включён (читает ini сам: P64 в реестре
//   ПОСЛЕ P47/P53/P59). P64_StateGate: 1 — пропустить, 0 — обработчик не вызывать (Mode=1, тихий пропуск как у «души»).
bool P64_GateWanted();
int  P64_StateGate(void* mgr, int opcode, int userNum, const BYTE* pkt);
// Статистика P64 (экспорт P64_GetStats/P64_ResetState/P64_QueryOpcode — для стенда tools/stand_p64).
struct P64_Stats
{
    LONG checked;       // пакетов списка через гейт
    LONG notInGame;     // вид 40: CUser+0x190 == 0
    LONG dead;          // вид 41: CUser+0x4F != 0
    LONG busy;          // вид 42: обмен/биржа/лавка/рыбалка
    LONG soul;          // вид 43: SoulState == 1
    LONG possess;       // вид 44: партнёр > 0 && SoulState == 2
    LONG refused;       // отказов (Mode=1)
    LONG journaled;     // строк журнала/лога (после ограничителя)
    LONG suppressed;    // подавлено ограничителем
};
PatchResult P66_PositionGuard();            // античит A7 (L6, A10): сверка с серверной клеткой/состоянием — 5012 подбор, 5427 зов друга, 6093 воскрешение, 5428 конец копания (2026-10-12)
PatchResult P67_GachaRewardVariant();       // античит A7 (A2, крит 5): 6581 вариант приза премиум-гачи из семейства приза (LinkWord коробки, приз из PrimiumGaChaTable); 6579 результат рулетки только при активной рулетке на финальной клетке (2026-10-12)
// Статистика P67 (экспорт P67_GetStats — для стенда tools/stand_p67): проверено 6581 / нарушений / отказов / проверено 6579 / нарушений 6579.
extern "C" void __stdcall P67_GetStats(int* checked, int* viol, int* refused, int* soulChecked, int* soulViol);
PatchResult P68_CharNameGuard();            // античит A13: имя персонажа 6138/6140 по правилам оригинального клиента; 2453 — имя в памяти только при флаге БД 1 (2026-10-13)
// Статистика/правило P68 (экспорт — для стенда tools/stand_p68): та же функция вердикта, что у площадок.
extern "C" __declspec(dllexport) int  __stdcall P68_NameVerdict(const BYTE* field20, int charset, int* len, int* pos, int* bad);
extern "C" __declspec(dllexport) void __stdcall P68_GetStats(int* c6138, int* c6140, int* viol, int* notChecked, int* refused, int* kept, int* db2453);
// ★ integ3: число 6138/6140 операторов, пропущенных без проверки (OperatorExempt=1) — для стенда.
extern "C" __declspec(dllexport) int  __stdcall P68_GetOperatorExempt();

// ── ОБЩАЯ ТОЧКА P47 (acdb) ─────────────────────────────────────────────────
//   IPv4 пира по userNum (сетевой порядок; 0 — не определён), getpeername с проверкой результата.
//   Определена в p47_identity_operator_gate.cpp; зовут журнал P53 и P48.
DWORD P47_PeerIpv4(int userNum);
// ★ integ3 (13.10.2026): отправитель — оператор (GM-флаг CUser+0x40B9F == 1 через sub_52ED50(mgr, userNum)) — тот же
//   признак, что у гейта операторских опкодов P47. mgr — this обработчика (CUserManager). Зовут P47_OperatorGate и P68.
bool P47_IsGmUser(void* mgr, int userNum);

// ── ★ ОБЩИЕ ТОЧКИ P48 ↔ P69 (autoban, 2026-10-14) ───────────────────────────
//   Определены в p48_kick_autoblock.cpp — одна логика «чья учётка у сессии» и один путь блока для счёта киков (P48)
//   и счёта нарушений целостности пакетов (P69).
//   P48_IdentityOf: по CUser — в мире ли (CUser+0x2E == 1), SoulState (CUser+0x182D3), учётка СЕССИИ: свой персонаж —
//   owner (CUser+0x174), вход соулмейтом (SoulState 2, soulSession=true) — iMateUserIndex CUser+0x182C6 (≤ 0 → 0, неизвестна).
struct P48_Identity
{
    bool inWorld;      // CUser+0x2E == 1 (CharMake/CharPortalMake после DB-логона, сверенного P50)
    int  soul;         // SoulState (CUser+0x182D3)
    bool soulMate;     // вход соулмейтом (SoulState 2 при soulSession)
    int  account;      // учётка сессии: >0; 0 — вход соулмейтом, iMateUserIndex ≤ 0 (неизвестна)
};
void P48_IdentityOf(const BYTE* user, int owner, bool soulSession, P48_Identity* out);
//   P48_SendHackBlock: штатный DB-запрос 2271 (как GM-блок 6094 / Recv_CharBlock) → DBManager sub_432950 →
//   `EXEC UPHackBlock UserIndex, часы` (−1 = 30 лет). mgr — CUserManager сессии. true — отправлен. SEH внутри.
bool P48_SendHackBlock(void* mgr, int userNum, int userIndex, int hours);

// ── ★ ОБЩИЕ ТОЧКИ P69 (autoban, 2026-10-14): ступенчатый автоблок за нарушения целостности пакетов ───────────────
//   Определены в p69_integrity_autoblock.cpp. Зовут: P47_OperatorGate (кэш CUserManager слота), P55 Report и P61
//   Report (учётка/адрес в журнал + счёт), P61 трамплины (IP пира раз на соединение, сброс слота), P48 (метка кика).
struct P69_Session
{
    void* mgr;        // CUserManager (переданный; nullptr на входе → кэш слота от гейта P47); nullptr — неизвестен
    BYTE* user;       // CUser; nullptr — нет
    int   account;    // учётка СЕССИИ, подтверждённая (сессия в мире; соулмейт — iMateUserIndex); 0 — неизвестна (до входа)
    int   owner;      // CUser+0x174: до входа в мир — заявлено клиентом (20000); у соулмейта — хозяин персонажа; ≤0 — нет
    int   soul;       // SoulState (CUser+0x182D3); −1 — нет CUser
    int   state;      // 0 до входа в мир, 1 в мире (свой), 2 в мире (вход соулмейтом), 3 соулмейт — учётка сессии неизвестна; −1 нет CUser
    int   charSlot;   // CUser+0x18C; −1 — нет
    bool  gm;         // GM-флаг (P47_IsGmUser: sub_52ED50 == 1)
};
bool  P69_ResolveSession(void* mgr, int userNum, P69_Session* s);   // false — CUser не найден (s заполнен «нет»)
void  P69_OnClientPacket(void* mgr, int userNum);                   // гейт P47 (0x42AB4F): запомнить CUserManager слота
void  P69_SlotReset(int slot);                                      // P61 SetConnectFlag (accept/разрыв): забыть слот
void  P69_NoteSlotIp(int slot);                                     // P61 приём: IP пира раз на соединение (getpeername)
DWORD P69_SlotIp(int slot);                                         // живой getpeername, при отказе — IP соединения из кэша
constexpr int kP69SrcP55 = 1;                                       // источник: валидатор пакетов P55 (виды 1..4)
constexpr int kP69SrcP61 = 2;                                       // источник: нарушение защищённого канала P61 (виды 56..59)
void  P69_OnViolation(const P69_Session& s, int userNum, int source, int kind, DWORD ip, int opcode);
bool  P69_TakeKickMark(int userNum, int account);                   // P48: кик после автоблока P69 (KickOnBlock) — не считать
PatchResult P69_IntegrityAutoBlock();       // античит autoban: ступенчатый автоблок за нарушения целостности пакетов — 20 → сутки, 50 → месяц, больше → бессрочно (2026-10-14)
// ★ P71 (оборона dev-сервера, 2026-10-15): четыре абсолютных срока GameServer (хранитель души, согласие отряда, штраф лагеря
//   CUser+0x3F454, предметы на земле) сравниваются с GetTickCount модульно — переход такта через 2^32 (29.10.2026) и аптайм ≥ 2^31
//   их не «вешают»; штраф лагеря из БД (секунды) теперь срок от момента записи, на разрыв в БД уходит остаток.
PatchResult P71_TickDeadlineWrap();         // модульные сравнения сроков GameServer при переходе GetTickCount через 2^32 (2026-10-15)
// Статистика P69 (экспорт P69_GetStats — для стенда tools/stand_p69).
struct P69_Stats
{
    LONG seen;         // нарушений пришло (все источники)
    LONG notKind;      // вид не из списка CountP55Kinds/CountChannelKinds
    LONG preWorld;     // учётка неизвестна (до входа в мир / соулмейт без iMateUserIndex) — только журнал
    LONG operators;    // оператор (GM-флаг) — не засчитано
    LONG counted;      // засчитано учётке
    LONG stages;       // ступеней достигнуто (строк ac.other 62)
    LONG sent;         // Mode=1: запросов 2271 отправлено
    LONG sendFailed;   // Mode=1: 2271 не отправлен (повтор ступени на следующем нарушении)
    LONG wouldBlock;   // Mode=0: «был бы блок»
    LONG kickMarks;    // Mode=1 + KickOnBlock: сессий помечено к штатному кику Hack Packet
    LONG ipFromCache;  // IP взят из кэша соединения (живой getpeername отказал)
};

// ★ P72 — БЕЗОПАСНОСТЬ (2026-10-15): обезвреживание скрытой закладки «CharItemKeeping(11)» стокового GameServer — кодовая
//   комбинация 5 предметных действий взводила периодическое затирание базового блока персонажа (CUser+0x174, 0x45 б) у всех 550
//   слотов процесса (RunProcess 10024 @0x4C2735). Мера 1: jne→jmp @0x4C2745 (ветка сброса всегда). Мера 2: трамплин @0x50A651
//   (шаг 5) — флаги CThread+0x51AC..0x51B4 обнуляются, журнал ac.other 76 + Log_Operator, по ключу AutoBlock — 2271 (P48_SendHackBlock).
PatchResult P72_HiddenWipeDisarm();         // безопасность: закладка CharItemKeeping(11) — таймер затирания отключён, взвод перехвачен (2026-10-15)
// Статистика P72 (экспорт P72_GetStats — для стенда tools/stand_p72).
struct P72_Stats
{
    LONG caught;       // комбинаций набрано (трамплин сработал)
    LONG clearFailed;  // флаги CThread обнулить не удалось (нет объекта потока / исключение)
    LONG routeSilent;  // маршрут 0: обычная сдача (0x50A6EB)
    LONG routeStock;   // маршрут 1: как сток — 5009 код 5 (0x50A6B6)
    LONG blockSent;    // AutoBlock=1: 2271 отправлен
    LONG blockFailed;  // AutoBlock=1: 2271 не отправлен (нет учётки сессии / отказ)
};
extern "C" __declspec(dllexport) int  __stdcall P72_OnArmed(void* mgr, int userNum);   // C-часть трамплина (экспорт — для verify/стенда)
extern "C" __declspec(dllexport) void __stdcall P72_GetStats(P72_Stats* out);

// ★ P73 — МОСТ EAC (античит EAC, этап Э1-В, 2026-10-16; контракт Reports/anticheat/eac/CONTRACT.md §4–§6): фоновая нить —
//   TCP-клиент к сайдкару AsdaEacServer 127.0.0.1:Port (15702): HELLO, PING 5 с, LOGIN на успехе 4001/5058, LOGOUT на разрыве
//   (SetConnectFlag 0), после переподключения — LOGIN всех в игре. KICK сайдкара → очередь слота → кик в нити карты на проходе
//   CheckDisConnectUser (0x526CEB, только Mode=1): сверка CUser+0x174, штатная пара Send_DisConnectType(KickType) + 0x526E40.
//   Журнал ac.other 77–84. Общие точки: стабы логона P47 (P47_LogonHooked), детур SetConnectFlag P61 (P61_SetConnHooked).
PatchResult P73_EacBridge();                // античит EAC: мост GameServer/Indun ↔ сайдкар (LOGIN/LOGOUT/KICK), Enabled=0 (2026-10-16)
extern "C" void __stdcall P73_OnLogon(int kind, int userNum, BYTE* user, int userIndex);   // успех 4001 (kind 1) / 5058 (kind 2) — LOGIN
extern "C" void __stdcall P73_OnConnFlag(int slot, int flag);                               // SetConnectFlag(slot, flag) — LOGOUT сессии слота
extern "C" int  __stdcall P73_OnCheckUser(void* mgr, int userNum, BYTE* user);              // нить карты: 1 — выведен по KICK
extern "C" void __stdcall P73_OnCommunityRes(void* mgr, int userNum);                       // ★ ред. 2: после стокового 2145 — REBIND
int  P73_KickInProgress();                  // в этой нити идёт кик P73: 0 — нет, иначе 0x100 | ourReason (P48 не считает, P58 — «EAC(P73)»)
bool P47_LogonHooked();                     // P47 поставил стабы 0x527692/0x52CD3E (Match20000) — P73 зовётся из P47_LogonMatch
bool P61_SetConnHooked();                   // P61 поставил детур 0x562910 — P73 зовётся из P61_ResetSlotC
// ★ EAC ред. 3 (контракт §8.1): привязка канала слота — ServerChannel::ChannelBinding соединения слота (32 б). Определена в
//   p61_traffic_encryption.cpp (AsdaWire::SlotChannelBinding под замком слота моста — НЕ звать под замком Ciocp). false (out не
//   определён) — P61 не поставлен / Legacy / рукопожатие не завершено / слот сброшен. Зовёт P73 на LOGIN (нить карты).
bool P61_SlotBinding(int slot, BYTE out[32]);
// Статистика P73 (экспорт P73_GetStats — для стенда tools/stand_p73).
struct P73_Stats
{
    LONG logons;        // LOGIN-событий (успех 4001/5058)
    LONG logouts;       // LOGOUT-событий (разрыв/accept слота с живой записью)
    LONG loginSent;     // кадров LOGIN отправлено (в т. ч. повторная рассылка после подключения)
    LONG logoutSent;    // кадров LOGOUT отправлено
    LONG pingSent;      // PING отправлено
    LONG pongReceived;  // PONG получено
    LONG kickReceived;  // KICK получено
    LONG kickQueued;    // KICK поставлено в очередь слота (Mode=1)
    LONG kickDone;      // KICK выполнено
    LONG kickDropped;   // KICK отброшено: слот не совпал / сессия ушла / перелогин
    LONG kickExpired;   // KICK отброшено по сроку KickPendingSec
    LONG kickOperator;  // KICK не выполнено: оператор (GM-флаг)
    LONG queueDropped;  // событий LOGIN/LOGOUT отброшено при переполнении кольца
    LONG connects;      // подключений к сайдкару (HELLO ушёл)
    LONG disconnects;   // потерь соединения после подключения
    LONG protoErrors;   // нарушений протокола сайдкаром
    LONG rebinds;       // ★ ред. 2: REBIND-событий (вход соулмейтом, учётка сессии из 2145)
    LONG rebindSent;    // ★ ред. 2: кадров REBIND отправлено (в т. ч. повторно после подключения)
    LONG loginBindZero; // ★ ред. 3: LOGIN-событий с нулевым bind (Legacy / P61 нет / рукопожатие не завершено)
    LONG loginRaced;    // ★ §8.6 R3-06: логонов без LOGIN — соединение слота сменилось, пока собирался LOGIN
};
extern "C" __declspec(dllexport) void __stdcall P73_GetStats(P73_Stats* out);

// ★ P74 — HP ИГРОКА СОСЕДЯМ ПО СЕКТОРУ (синхронизация боя, фаза Ф3, 2026-10-17; проект Reports/combat_sync_2026-10-17/03_DESIGN.md §6):
//   снимок HP 4058 после урона (sub_43C690, 0x43C854) и изменений во времени (SetCurrentHpTimeValue, ветка «не 2/4», 0x43CE82)
//   сток шлёт только себе; P74 — себе как сток + пакет сектору 3×3 кроме себя (sub_52E6D0). Урон — только sub_43C690 с a5=1
//   (навыки, урон по времени, отражение; обычные удары мобов и обычная атака PvP идут с a5=0 — не покрыты). Тихие типы — как
//   есть; ред. 2 (Version 46): типы 1/6 (мгновенное лечение) — тихой копией (+10 = 0, +11 = −1); скрытый оператор — нет;
//   прореживание по умолчанию выключено (RegenMinIntervalMs=0).
PatchResult P74_HpSectorSync();             // синхронизация боя Ф3: 4058 соседям (урон навыков + реген/лечение/яд/зелья), 2026-10-17
extern "C" void __stdcall P74_AfterSelfSend(void* net, int op, int to, const BYTE* body, int site);   // C-часть заглушек S1/S2
// Статистика P74 (экспорт P74_GetStats — для стенда tools/stand_p74). Индекс [1] — урон (S1), [2] — время (S2); [0] не используется.
struct P74_Stats
{
    LONG seen[3];          // вызовов заглушки (пакет себе ушёл)
    LONG sent[3];          // рассылок соседям
    LONG skipThrottle[3];  // пропущено прореживанием
    LONG skipType;         // пропущено: тип не «тихий» / не из маски
    LONG skipHidden;       // пропущено: скрытый оператор
    LONG skipBad;          // пропущено: номер вне 0..549 / тело не того игрока / нет менеджера
    LONG faults;           // исключений при чтении/отправке
    LONG sentInstant;      // ★ ред. 2: из sent[2] — тихих копий типов 1/6 (мгновенное лечение)
};
extern "C" __declspec(dllexport) void __stdcall P74_GetStats(P74_Stats* out);

// ★ P75 — ЗЕЛЬЕ ПОВЫШЕНИЯ УРОВНЯ (предмет 558, слово владельца 19.10.2026; документ GameServer/level-up-potion-p75.md):
//   шаг 1 (5450, до БД, площадка 0x4EDDC7 `call 0x4F27F0`) — отказ 5451 код 0 при уровне ≥ TargetLevel / потолке P29 ниже /
//   негодной ExpTable или записи Function_Table; +37 (бафф заглушки) в памяти → 0. Шаг 2 (ответ БД, 0x4EF606 `call 0x4F2640`) —
//   начисление ExpTable[TargetLevel] − опыт штатной Recv_BattleServerFromCharParamExp_1 (награда, a5=1) по уровню за вызов,
//   без множителей. 4036 — один раз на последнем уровне (0x4CBFEC/0x4CC009), кувшин души от зелья не наполняется
//   (0x4CC08D/0x4CC27E) — только внутри начисления (TLS). ★ ред. 2: «один раз на персонажа» — гейт уровня шага 1 (SQL-часть снята);
//   замок «зелье в пути» на слот: ставится при уходе 2140 в БД (0x4EF02E), снимается в шаге 2 / по тайм-ауту / на выходе
//   (ClearUserMemory: общая точка P63_OnUserClear → P75_OnUserClear, без P63 — своя площадка 0x527374).
PatchResult P75_LevelUpPotion();            // зелье повышения уровня 558: до 70 уровня вычислением опыта, 2026-10-19
extern "C" int  __stdcall P75_UseGate(void* self, int num, int code);       // шаг 1: 1 — отказ (5451 код 0)
extern "C" void __stdcall P75_AfterDbUse(void* self, int num, int code);    // шаг 2: начисление после ответа БД
extern "C" int  __stdcall P75_SkipSend(int kind);                           // 1/2 — 4036 себе/сектору, 3 — кувшин души
extern "C" void __stdcall P75_OnDbSend(void* mgr, int op, const BYTE* body, int num);   // уход 2140 в БД: замок «в пути»
extern "C" void __stdcall P75_OnUserClear(int num);                          // выход сессии слота: снять замок (общая точка P63)
bool P63_ClearHooked();                     // P63 записал площадку ClearUserMemory 0x527374 (тогда P75 зовётся из P63_OnUserClear)
// Статистика P75 (экспорт P75_GetStats — для стенда tools/stand_p75).
struct P75_Stats
{
    LONG gateSeen;         // шаг 1: 5450 с кодом зелья
    LONG gatePassed;       // шаг 1: пропущено дальше (к штатным проверкам и в БД)
    LONG refused[8];       // шаг 1: отказов по причине (1 уровень, 2 потолок P29, 3 ExpTable, 4 запись, 5 нет персонажа, 6 исключение,
                           //   7 замок «зелье в пути»)
    LONG dbSeen;           // шаг 2: ответ БД с кодом зелья (предмет списан БД)
    LONG dbNoGrant;        // шаг 2: условия к ответу БД уже не выполнены — опыта нет
    LONG granted;          // начислено полностью (уровень = цель, опыт = ExpTable[цель])
    LONG grantShort;       // начисление оборвалось раньше цели
    LONG levelsGranted;    // уровней всего
    LONG skipped4036;      // 4036 себе подавлено (промежуточные уровни)
    LONG skippedJar;       // вызовов кувшина души подавлено
    LONG fallback4036;     // резервных 4036 (обрыв после подавления)
    LONG faults;           // исключений
    LONG lockSet;          // ★ ред. 2: замков «в пути» поставлено (уход 2140)
    LONG lockReleased;     // снято шагом 2
    LONG lockExpired;      // истекло по тайм-ауту (обнаружено при следующем 5450 того же персонажа)
    LONG lockCleared;      // снято на выходе сессии (ClearUserMemory)
};
extern "C" __declspec(dllexport) void __stdcall P75_GetStats(P75_Stats* out);

// ★ P76 — ПРОВЕРКА ПОЛЕЙ ПАКЕТОВ ЖИВЫХ КАМНЕЙ 5022/5024/5031 (решение владельца 21.10.2026; документ GameServer/sowel-slot-bounds-p76.md):
//   вместо `call sub_52BFF0` (0x4DBDEF / 0x4DC51E / 0x4DE70E) — сток + сверка полей тела с правилами честного клиента;
//   вне пределов — штатный отказ кодом 0 до любой записи. Журнал ac.other 85…87.
PatchResult P76_SowelSlotBounds();          // поля пакетов живых камней: гнездо 0..3, контейнеры, 2026-10-21
extern "C" int  __stdcall P76_Check(int site, void* self, BYTE* ebp);   // 1 — отказ
extern "C" __declspec(dllexport) void __stdcall P76_GetStats(int* checked, int* viol, int* refused, int* journaled, int* suppressed);

// ★ P77 — ТОЧКА МОЛЧАЛИВОЙ ОСТАНОВКИ ХОДА → КЛИЕНТУ (решение владельца 22.10.2026; документ GameServer/move-sync-stop-point-p77.md):
//   MoveSyncProcess@0x5427D0 на «iMotionStartTime = 0» / «iMovePos - Value2» / «iMovePos Max Over» / «don't move tile»
//   (`call 0x542520` 0x542968 / 0x542ACB / 0x542B11 / 0x542B49) снимал игрока со стека хода БЕЗ пакета клиенту — следующий 4006
//   давал «CharMove Hack Position». Теперь после стока — штатный 4009 в точку сервера себе и сектору (как CharStop «Revision Pos»).
PatchResult P77_MoveSyncStopPoint();        // 4009 в точку сервера при молчаливой остановке MoveSyncProcess, 2026-10-22
// Статистика P77 (экспорт P77_GetStats — для стенда tools/stand_p77). Индекс [1..4] = площадки S1..S4.
struct P77_Stats
{
    LONG seen[5];          // вызовов площадки (сток снял/не снял — до проверок)
    LONG sentSelf[5];      // ушёл 4009 себе
    LONG sentSector;       // ушёл 4009 сектору
    LONG skipNotRemoved;   // сток не снял со стека (флаг CUser+0x33 не перешёл 1 → 0)
    LONG skipNotInGame;    // сессия не в игре / нет нити или менеджера
    LONG skipBadPoint;     // точка сервера не годится (≤ 0 / не число)
    LONG skipInterval;     // пол MinIntervalMs
    LONG skipHidden;       // скрытый оператор — сектору не шлём
    LONG skipNoUser;       // номер вне 0..549 / нет CUser
    LONG faults;           // исключение при чтении CUser / отправке
};
extern "C" __declspec(dllexport) void __stdcall P77_GetStats(P77_Stats* out);

// ★ P80 — ХОД ВПРИСЯДКУ ×0.5 И ПРЫЖОК С БЕГА СОСЕДЯМ (решение владельца 24.10.2026; документ GameServer/crouch-speed-jump-relay-p80.md):
//   S1 RecalcMoveSpeed@0x5588F0 (площадка 0x558B39): статус хода CUser+0x54E4 == CrouchStatus (4006 @+3 = 4 у клиента в приседе)
//   → стоковое деление скорости на 2, как при состояниях 112/186 (без двойного деления). S2 CharEMotionSync sub_546730 (площадка
//   0x5468C1): 4024 с кодом RelayWhileMoving (131, прыжок) в ходу → 4025 сектору (сток в ходу выходил без рассылки).
PatchResult P80_CrouchSpeedJumpRelay();     // скорость приседа ×0.5 и прыжок с бега соседям, 2026-10-24
// Статистика P80 (экспорт P80_GetStats — для стенда tools/stand_p80).
struct P80_Stats
{
    LONG crouchHalved;     // S1: скорость поделена по статусу приседа
    LONG hide186;          // S1: поделена по состоянию 186 (стоковая ветка трамплина)
    LONG relayed;          // S2: 4024 кода RelayWhileMoving в ходу разослан соседям
    LONG droppedMoving;    // S2: 4024 другого кода в ходу — выход, как сток
};
extern "C" __declspec(dllexport) void __stdcall P80_GetStats(P80_Stats* out);

// ★ P81 — СТРАЖ КОДА ДЕЙСТВИЯ 4024 И ЧАСТОТЫ «Dancer» (решение владельца 24.10.2026; документ GameServer/action-code-guard-p81.md):
//   CharEMotionSync sub_546730: код тела вне AllowedCodes от НЕ-оператора (200 «мёртв», 300/301 «скрытый оператор» и пр.) —
//   выход без записи CUser+0x54E4 и без 4025 (площадка A 0x5468E1 «стоя», B 0x546952 «в ходу» — путь P80 S2); танец 112/113 —
//   sub_54A050 («Dancer», индекс 13) не чаще DanceCountMinSec (площадка C 0x546978). Журнал ac.other 88/89/90.
PatchResult P81_ActionCodeGuard();          // страж кода 4024 и частоты звания «Dancer», 2026-10-24
extern "C" int __stdcall P81_Check(int site, BYTE* ebp, int code);   // 1 — отклонить (трамплины A/B, медленный путь)
extern "C" int __stdcall P81_Dance(BYTE* ebp);                       // 0 — не засчитывать «Dancer» (трамплин C)
// Статистика P81 (экспорт P81_GetStats — для стенда tools/stand_p81).
struct P81_Stats
{
    LONG violStanding;     // A: код вне разрешённых, не оператор (стоя)
    LONG violMoving;       // B: то же в ходу (путь P80 S2)
    LONG refused;          // отклонено (Mode=1)
    LONG journalOnly;      // пропущено как сток (Mode=0)
    LONG operatorPassed;   // код вне разрешённых от оператора — как сток
    LONG danceCounted;     // C: «Dancer» засчитан (sub_54A050 позван)
    LONG danceFast;        // C: 112/113 чаще DanceCountMinSec
    LONG danceSkipped;     // C: не засчитан (Mode=1)
    LONG journaled;        // строк поставлено в журнал P53
    LONG suppressed;       // строк подавлено интервалом JournalIntervalSec
    LONG faults;           // исключение при чтении кадра/CUser
};
extern "C" __declspec(dllexport) void __stdcall P81_GetStats(P81_Stats* out);

// ★ P82 — ОТКАТ ФУНКЦИОНАЛЬНЫХ ПРЕДМЕТОВ С КОДОМ ≥ 600 (решение координатора 24.10.2026; документ GameServer/func-cooltime-ext-p82.md):
//   стоковая таблица отката по коду CUser+0x3BC41 — 600 записей; sub_4F27F0 для кода ≥ 600 всегда 0 (5451 код 8 — маунты fable
//   600…637 не применялись). Своя таблица по слоту: C 0x4F2820 (проверка), G 0x4F2672 (регистрация), T 0x543353 (такт, 5452),
//   S 0x52F374 (сохранение в 2157), R1 0x5290BE / R2 0x52E23A (восстановление: страж — код ≥ 600 в CUser не пишется; в таблице —
//   своя запись + тело 5465 + групповой откат), Z 0x527399 (ClearUserMemory). Журнал ac.other 91…93.
PatchResult P82_FuncCoolTimeExt();          // откат функциональных предметов с кодом >= 600 (своя таблица), 2026-10-24
// ★ P85 — ПРЕМИУМ-КОРЗИНА ЦЕЛИКОМ (слово владельца 25.10.2026; пара DBPatch P85 + SQL premrows + шлюз gp7): коды всех позиций
//   5070 в хвост запроса шлюзу (ветка 137 sub_4F60E0). Площадка 0x4F62AC. Журнал ac.other 100–101 (102 — DBPatch).
PatchResult P85_PremiumCartRows();          // корзина 5070 целиком в запрос шлюзу gp7, 2026-10-25
extern "C" void __stdcall P85_OnCartRequest(int num, BYTE* req, const BYTE* cart, const BYTE* cartOrig);   // запись расширения корзины (r2: коды пакета 5070)
extern "C" int  __stdcall P82_Check(void* self, int num, int code);      // C: 1 — можно, 0 — отказ 8
extern "C" void __stdcall P82_Register(void* self, int num, int code);   // G: регистрация (ответ БД 2141)
extern "C" void __stdcall P82_Tick(void* self, int num);                 // T: истечение → 5452
extern "C" void __stdcall P82_OnSave(void* self, BYTE* body, int num);   // S: тело 2157 — свои откаты в свободные места
extern "C" void __stdcall P82_OnRestore(int site, BYTE* ebp);            // R1/R2: запись восстановления с кодом >= 600
extern "C" void __stdcall P82_OnUserClear(int num);                      // Z: выход сессии — сброс слота
// Статистика P82 (экспорт P82_GetStats — для стенда tools/stand_p82).
struct P82_Stats
{
    LONG checkSeen;        // C: проверок кода >= 600
    LONG checkActive;      // C: отказ — откат активен (5451 код 8)
    LONG tableFull;        // своя таблица слота заполнена (отказ 8 / регистрация / восстановление не записаны)
    LONG regAdded;         // G: откат записан
    LONG regActive;        // G: запись уже активна — как сток, не обновляется
    LONG regNoDur;         // G: +18 <= 0 — отката нет (как сток)
    LONG expired;          // откатов истекло (такт T или сохранение S)
    LONG sent5452;         // 5452 отправлено
    LONG saved;            // S: записей дописано в тело 2157
    LONG saveShort;        // S: остаток <= 2 с — не сохраняется (правило стока)
    LONG saveNoRoom;       // S: в блоке 2157 нет свободного места (журнал 92)
    LONG restored;         // R: восстановлено в свою таблицу (+ тело 5465)
    LONG restoreBad;       // R: код вне Function_Table — отброшен (журнал 91)
    LONG restoreOff;       // R: механика выключена (Enabled=0 / SaveRestore=0) — отброшен стражем
    LONG groupSet;         // R: групповой откат поставлен (sub_4DA920)
    LONG cleared;          // Z: слот очищен на выходе
    LONG staleReset;       // слот сброшен: другой Userindex (выход не дошёл до Z)
    LONG journaled;        // строк поставлено в журнал P53
    LONG suppressed;       // строк подавлено интервалом JournalIntervalSec
    LONG faults;           // исключений
};
extern "C" __declspec(dllexport) void __stdcall P82_GetStats(P82_Stats* out);

// ★ P87 — [ИСПРАВЛЕНИЕ] СТАРТОВЫЕ НАВЫКИ 4-Й ПРОФЕССИИ ПО ПОДКЛАССУ (дефект оригинала, 26.10.2026): sub_481CE0 LABEL_99 выдавал
//   строку ChangeJobAddSkillTable ОСНОВНОГО класса CUser+0x190 (3/14/25) вместо подкласса CUser+0x191 (4/15/26). Площадка
//   0x4820C9 (7 б). Строки нет (6/17/28) — сток. Звание 24/25/26 из sub_48A8C0 сохранено. Журнал ac.other 106–108.
PatchResult P87_Job4StartSkills();          // стартовые навыки 4-й профессии по строке подкласса, 2026-10-26
extern "C" int __stdcall P87_PickRow(BYTE* skill, BYTE* user, int userNum, int a3, int stockRow);   // строка таблицы для sub_48A8C0
// Статистика P87 (экспорт P87_GetStats — для стенда tools/stand_p87).
struct P87_Stats
{
    LONG seen;         // вызовов площадки (LABEL_99)
    LONG picked;       // выдано по строке подкласса (вид 106)
    LONG noRow;        // строки подкласса нет / вне 1…39 — сток (вид 107)
    LONG titleCalls;   // вызовов sub_54A050 за sub_48A8C0 (звание 24/25/26, как сток)
    LONG faults;       // исключений (вид 108)
    LONG journaled;    // строк поставлено в журнал P53
};
extern "C" __declspec(dllexport) void __stdcall P87_GetStats(P87_Stats* out);

// ★ P88 — [ПОРТ] СОБЫТИЯ ЗВАНИЙ 187–205 (задача владельца 26.10.2026, документ GameServer/title-events-p88.md): у 188…205
//   в стоке нет ни одного вызова накопителя sub_54A050, у 187 — только из Recv_UserSoulResult с add 0. Площадки:
//   A 0x4CBA1A убийство на войне фракций (187–189), B1/B2 0x4EFE7D/0x4EFEDD сброс навыков (190), C 0x4EFE24 склад до
//   предела (191), D 0x53EF2A ремесло 2666 (192 зелья, 193–195 «Герой», 196–198 «Легенда»), E 0x546F8B находка копки
//   (199–201 зоны, 203 живой камень), F 0x456F45 уровень питомца (202), G 0x4D5CB8 подбор билета (205). Журнал ac.other 109–111.
PatchResult P88_TitleEvents();              // события званий 187–205 через стоковый накопитель, 2026-10-26
extern "C" void __stdcall P88_OnSite(int site, BYTE* ebp);                                                   // трамплины A–E, G
extern "C" char __fastcall P88_PetLevel(void* userMng, void* edx, int userNum, int title, int level, int extra);   // F
// Статистика P88 (экспорт P88_GetStats — для стенда tools/stand_p88).
struct P88_Stats
{
    LONG warKills;       // A: убийств на войне фракций (сток начислил очки отряду)
    LONG resets;         // B: сбросов навыков предметом
    LONG wareExpands;    // C: расширений склада
    LONG crafts;         // D: успешных изготовлений с продуктом
    LONG craftNoProduct; // D: ответ 2666 == 1 без продукта (провал броска)
    LONG digFinds;       // E: находок копки
    LONG petLevels;      // F: повышений уровня питомца
    LONG tickets;        // G: подборов кода из TicketCodes
    LONG counted;        // вызовов стокового накопителя sub_54A050
    LONG granted;        // званий выдано этими вызовами (вид 109)
    LONG owned;          // событие пропущено — звание уже есть
    LONG notReady;       // событие пропущено — строка FameInfo выключена / не накопитель (вид 110)
    LONG faults;         // исключений (вид 111)
    LONG journaled;      // строк поставлено в журнал P53
};
extern "C" __declspec(dllexport) void __stdcall P88_GetStats(P88_Stats* out);

// ★ P89 — [ИСПРАВЛЕНИЕ] ГЕЙТ СТАРТОВЫХ НАВЫКОВ 4-Й ПРОФЕССИИ ПО ВЕТКЕ (дефект оригинала, 26.10.2026, документ
//   GameServer/job4-gate-branch-p89.md): sub_481CE0 проверял «0 очков в категориях 4-й профессии» парами 10/11 (боец — верно),
//   12/13 (лучник, дерево — 11), 14/15 (маг, дерево — 12) — у лучника/мага с ровно 60 очками каждое очко в дереве 11/12
//   повторно выдавало стартовую строку (уровень 0). Площадка 0x481D3F (диспетчер switch, 17 б): категория своей ветки
//   10/11/12; повтор уже выданной строки подкласса (P87) не выдаётся. Mode=0 — только журнал. Журнал ac.other 112–114.
PatchResult P89_Job4GateBranch();           // гейт стартовых навыков 4-й профессии по категории ветки, 2026-10-26
extern "C" DWORD __stdcall P89_Dispatch(BYTE* skill, BYTE* user, int userNum, int a3);   // адрес продолжения switch
// Статистика P89 (экспорт P89_GetStats — для стенда tools/stand_p89).
struct P89_Stats
{
    LONG seen;         // входов в диспетчер (подкласс 4…28)
    LONG job4;         // из них подклассы 4/6/15/17/26/28
    LONG stockGrant;   // гейт стока пропустил бы
    LONG fixGrant;     // гейт по ветке пропускает
    LONG diverged;     // решения разошлись (вид 112)
    LONG ownedSkip;    // строка подкласса уже выдана целиком (вид 113)
    LONG faults;       // исключений (вид 114)
    LONG journaled;    // строк поставлено в журнал P53
};
extern "C" __declspec(dllexport) void __stdcall P89_GetStats(P89_Stats* out);

// ★ P91 — [ИСПРАВЛЕНИЕ] ПОТОЛОК ОПЫТА ЗА МОБА МАСШТАБИРУЕТСЯ РЕЙТОМ СОБЫТИЯ (решение владельца 26.10, волна exprate;
//   документ GameServer/exp-cap-rate-p91.md): сток режет опыт моба до 1/9 уровня (0x4CBC09 одиночка, 0x4C8012 отряд) ПОСЛЕ
//   рейта — на ур. 1–3 x2/x3/x5 одинаковы. Потолок = уровень × max(1, fEvent + LuckyHours) / CapDivisor (≤ уровня); личные %
//   не входят. CapScalesWithRate=0 + CapDivisor=9 — сток. Журнал ac.other 118/119.
PatchResult P91_ExpCapRate();               // потолок опыта за моба × рейт события, 2026-10-26
extern "C" void __stdcall P91_Cap(int site, int userNum, DWORD fevBits, __int64* range);   // новый потолок в *range
extern "C" __declspec(dllexport) void __stdcall P91_GetStats(LONG* out7);                  // статистика для stand_p91

// ★ P92 — [ИСПРАВЛЕНИЕ] ВРЕДНЫЙ ЭФФЕКТ НАВЫКА ИГРОКА — ТОЛЬКО НА ВРАЖДЕБНОГО ИГРОКА (задача владельца 26.10, волна bowfx;
//   документ GameServer/hostile-target-guard-p92.md): площадные проки 173 «Взрыв» (S1 0x486B3A) и 248 хранителя (S2 0x48722A)
//   били всех игроков вокруг без sub_556DB0; отражение 220 (S3 0x486E1A) сверялось с ID состояния (+52 = 0) — правило
//   перевёрнуто; записи 8009 NpcServer «цель-игрок» (S4 0x428453) — страховка от расхождения зеркала режима; 5256 (S5 0x46FCCB) —
//   навыки HostileSkills (1004 «Клеймо льда», +52 = 5) сверяются как враждебные. Правило — sub_556DB0(исполнитель, жертва, −1).
//   Mode=0 — только журнал. Журнал ac.other 121–123.
PatchResult P92_HostileTargetGuard();       // вредный эффект навыка — только на враждебного игрока, 2026-10-26
extern "C" int __stdcall P92_Decide(int site, BYTE* ebp);   // решение площадки (S1–S4: 1/0; S5: аргумент a4)
// Статистика P92 (экспорт P92_GetStats — для стенда tools/stand_p92). Индекс массивов — площадка 1…5 (0 не используется).
struct P92_Stats
{
    LONG checks[6];       // решений по площадке
    LONG refused[6];      // не применено (Mode=1; вид 121/122)
    LONG wouldRefuse[6];  // было бы не применено (Mode=0, сток)
    LONG allowedNew[6];   // S3/S5: сток запрещал, правило P92 разрешает (враждебной цели теперь достаётся)
    LONG selfSkip;        // свой площадной урон по себе не применён (S1/S3)
    LONG noUser;          // исполнитель или жертва не найдены — решение стока
    LONG faults;          // исключений (вид 123)
    LONG journaled;       // строк поставлено в журнал P53
    LONG suppressed;      // строк подавлено интервалом JournalIntervalSec
};
extern "C" __declspec(dllexport) void __stdcall P92_GetStats(P92_Stats* out);

// ★ P94 — [ИСПРАВЛЕНИЕ] СООБЩЕНИЯ ДРУГА НЕ УХОДЯТ САМОМУ СЕБЕ И ЧУЖОЙ ПАРЕ (волна charpos, 26.10; документ
//   GameServer/soulmate-self-echo-p94.md): номер слота Друга сервер берёт из устаревшей строки dbo.CharPos, и relay-сообщения
//   пары 3314/3310/3312/3320 приходили самому отправителю (5110 «Друг вошёл» о себе, запись себя Другом) или постороннему.
//   Площадки S1 recv_1 0x494631, S2 recvSoulMateStateInfo 0x493D2B, S3 sub_4949C0 0x494A2F, S4 sub_494010 0x49407C — после
//   стоковых проверок, до отправки клиенту. Mode=0 — только журнал. Журнал ac.other 130–132.
PatchResult P94_SoulmateSelfEcho();         // сообщения пары — не себе и не чужой паре, 2026-10-26
extern "C" int __stdcall P94_Decide(int site, BYTE* ebp);   // 1 — отправлять (сток), 0 — пропустить пакет
// Статистика P94 (экспорт P94_GetStats — для стенда tools/stand_p94). Индекс массивов — площадка 1…4 (0 не используется).
struct P94_Stats
{
    LONG checks[5];       // решений по площадке
    LONG passed[5];       // отправлено как в стоке (отправитель — другой игрок той же пары)
    LONG self[5];         // «себе» (вид 130)
    LONG foreign[5];      // «чужая пара» (вид 131)
    LONG dropped;         // не отправлено (Mode=1)
    LONG wouldDrop;       // было бы не отправлено (Mode=0, сток)
    LONG noUser;          // получателя нет — решение стока
    LONG faults;          // исключений (вид 132)
    LONG journaled;       // строк поставлено в журнал P53
    LONG suppressed;      // строк подавлено интервалом JournalIntervalSec
};
extern "C" __declspec(dllexport) void __stdcall P94_GetStats(P94_Stats* out);

// ★ P95 — [ИСПРАВЛЕНИЕ] ВСКРЫТИЕ КОРОБОК И МИН. УРОВЕНЬ ПРЕДМЕТОВ (баги игроков 29.10, волна bugs6; документ
//   GameServer/item-use-guard-p95.md): 6096 — позиции коробки раскладываются по правилу контейнера СЕРВЕРА (коды 7/11 на пустом
//   инвентаре из-за разных таблиц, затирание у самоцветов/особых) и мин. уровень коробки; 5468 бустер и 5028 расходник — мин.
//   уровень (+8). Площадки S1/S2 0x55AB2A, S3 0x4F4BC5, S4 0x4D8F30. Журнал ac.other 140–144.
PatchResult P95_ItemUseGuard();             // коробки 6096 (раскладка + уровень), бустер 5468 и расходник 5028 (уровень), 2026-10-29
extern "C" int __stdcall P95_OnPackage(BYTE* ebp);   // 6096: 0 — сток (тело приведено), 1 — отказ (код в [ebp-3C1h])
extern "C" int __stdcall P95_OnGacha(BYTE* ebp);     // 5468: 0 — сток, 1 — отказ (код в [ebp-0D0h])
extern "C" int __stdcall P95_OnSpend(BYTE* ebp);     // 5028: 0 — сток, 1 — отказ (5029 код 0)
// Статистика P95 (экспорт P95_GetStats — для стенда tools/stand_p95). Индекс массивов — площадка 1 (6096), 2 (5468), 3 (5028).
struct P95_Stats
{
    LONG checks[4];       // решений по площадке
    LONG passed[4];       // прошло к стоку
    LONG refusedLevel[4]; // отказ по мин. уровню (виды 141/142/143)
    LONG positionsMoved;  // позиций коробок переразмещено (вид 140)
    LONG requestsMoved;   // запросов 6096 с переразмещением
    LONG noRoom;          // позиций без свободной ячейки в контейнере сервера
    LONG refusedNoRoom;   // отказов 6097 код 7 «нет места» от P95
    LONG unknownCode;     // позиций с кодом вне всех таблиц (не трогаются — сток: код 10)
    LONG faults;          // исключений (вид 144)
    LONG journaled;       // строк поставлено в журнал P53
    LONG suppressed;      // строк подавлено интервалом JournalIntervalSec
};
extern "C" __declspec(dllexport) void __stdcall P95_GetStats(P95_Stats* out);

// ── ОБЩАЯ ТОЧКА P49 ↔ P08 ───────────────────────────────────────────────────
//   Определена в p49_original_checks_restore.cpp. P08 (обход подписи 5450) не ставится,
//   когда P49 возвращает проверку с правильной длиной.
bool P49_FunctionItemMd5FullWanted();
// ★ sec2: счётчик Secret (CUser+4) ДО сброса стабом кика за повторы (sub_524440 «> 20» обнуляет его перед возвратом 1 — к
//   Send_DisConnectType он уже 0). user — CUser кика; −1 — стаб этого CUser не срабатывал (берётся один раз).
int  P49_TakeSecretPre(const BYTE* user);

// ── ОБЩИЕ ТОЧКИ P21 (закон port-shared-points) ──────────────────────────────
//   Определены в p21_title_mask_512.cpp. Нужны P24: снятие звания обязано
//   спрашивать владение и слать маски ТОЙ ЖЕ логикой, иначе звания 256…511
//   разъедутся — их бит лежит не в CUser, а в хвосте массива записей.
//   Работают и при выключенном P21: тогда видна только низкая половина (id < 256).
bool P21_FameOwned(void* pUser, int titleId);                                  // владеет ли званием
void P21_SendFameMask6066(void* fameSelf, void* pUser, int userNum);           // маска «получено» владельцу
void P21_SendFameMask6086(void* fameSelf, void* pUser, int userNum);           // маска «найдено»  владельцу

// ★ ДЕЙСТВУЮЩИЙ предел длины текста чата в байтах. Определён в
//   p14_chat_message_length.cpp, до установки P14 равен стоковым 80.
//   Читают и P14 (правки стока), и P13 (широкие каналы 6560) — чтобы у всех
//   чат-путей было ОДНО число, задаваемое [P14_ChatMessageLength] MaxTextLen.
extern int g_chatMaxTextLen;

// ★ P96 — СУМКА 30 → 60 (боковое хранилище DLL, 2026-10-30; бриф Reports/inventory_x2/P96_P97_BRIEF.md):
//   контейнер 1 — g_bag[550][60][57] в DLL; 9 роутеров, recvDB, 4045, PrimiumSum, EventItem, очистка;
//   19 imm 1E→3C; recvDB граница 0x5296B1 1E→3B; канарейка старой области. Журнал ac.other 145–147.
PatchResult P96_InventoryX2();
extern "C" __declspec(dllexport) int  __stdcall P96_BagSize();   // 60 если P96 встал, иначе 30 (для P95)
extern "C" __declspec(dllexport) bool __stdcall P96_Active();

// ★ P97 — ВЕС u16 (до 65535, потолок 60000; 2026-10-30; бриф Reports/inventory_x2/P96_P97_BRIEF.md):
//   129 movsx→movzx, 10 пересчётов регистром, 4 потолка 30000→60000, 5 трамплинов CraftEnter 0…65535.
PatchResult P97_WeightU16();
extern "C" __declspec(dllexport) bool __stdcall P97_WeightU16Active();   // для P35 CatStack

// ★ P98 — [ИСПРАВЛЕНИЕ] СТОПОЧНЫЙ ПРЕДМЕТ ИЗ ПРЕМИУМ-ПОЧТЫ = 1 ШТ. (волна bugs7, 30.10.2026; документ
//   GameServer/premium-stack-amount-p98.md): 11006 Recv_PremiumItemToInven_Req строит шаблон sub_5340B0(…, a4 = 0, …) — новая стопка
//   приходила с Amount 0 (предмет нерабочий), при существующей стопке N — с Amount N (дюп). Площадка S1 0x4F8636 (цель je после
//   «sub_5340B0 == 1»): шаблон +9 := 1, +14 := вес штуки. Путь P16 — P98_FixPremiumRecord. Журнал ac.other 150–152.
PatchResult P98_PremiumStackAmount();                                         // премиум-почта: стопка = 1 шт., 2026-10-30
extern "C" void __stdcall P98_OnPremium(BYTE* ebp);                           // 11006: приводит шаблон [ebp-5Fh] на месте
extern "C" __declspec(dllexport) int __stdcall P98_FixPremiumRecord(void* mgr, int userNum, int code, BYTE* rec, int count);   // путь P16 (экспорт — для стенда): 0 — не тронут, 1/2 — приведён
// Статистика P98 (экспорт P98_GetStats — для стенда tools/stand_p98).
struct P98_Stats
{
    LONG checks;          // решений (площадка 11006 + вызовы из P16)
    LONG notStack;        // шаблон не стопка ветки «расходник» (нестопочный, контейнер 1, тип 10, не item_list) — как сток
    LONG alreadyOne;      // стопка уже 1 шт. с весом штуки (существующая стопка из 1) — без изменений
    LONG fixedNew;        // новая стопка: Amount 0 → 1 (вид 150)
    LONG fixedCopied;     // шаблон скопировал стопку N → 1 (вид 151, дюп)
    LONG viaP16;          // вызовов P98_FixPremiumRecord (путь P16)
    LONG faults;          // исключений (вид 152)
    LONG journaled;       // строк поставлено в журнал P53
    LONG suppressed;      // строк подавлено интервалом JournalIntervalSec
};
extern "C" __declspec(dllexport) void __stdcall P98_GetStats(P98_Stats* out);

// ★ P99 — [ИСПРАВЛЕНИЕ] РАЗДЕЛЕНИЕ УЛУЧШЕНИЯ ВЫДАЁТ КАМЕНЬ СВОЕГО ТИПА (31.10.2026, окно 50500; документ
//   GameServer/upgrade-split-stone-p99.md): 6549 Recv_UserUpgradeExtraction — условия веток выбора готового камня меняются
//   местами (imm @0x534DD2 01→02, @0x534E88 02→01): оружие → 401 (204), прочее → 363 (206). Сток выдавал наоборот.
PatchResult P99_UpgradeSplitStone();                                          // разделение: камень своего типа, 2026-10-31

// ★ P100 — [ИСПРАВЛЕНИЕ] ЗАРЯДЫ СПЕЦПРЕДМЕТОВ СКЛАДЫВАЮТСЯ ПРИ ПОЛУЧЕНИИ (01.11.2026, решение владельца; проект
//   Reports/item_dedup/charges/P100_PROJECT.md): входящий спецпредмет (код 1…637, ключ из ConfigSet\charge_groups.txt > 0)
//   прибавляет заряды к первой по Posx ячейке сумки того же ключа (Cap 30000), код ячейки не меняется; 17 путей выдачи/переноса,
//   [ИСПРАВЛЕНИЕ 300] заряды выдачи — i32 вместо u8 FT+13. Журнал ac.other 153–157. Бит Sites 7 (подарок A8) — за P101.
PatchResult P100_ChargeStack();
extern "C" __declspec(dllexport) BYTE* __stdcall P96_BagRec(BYTE* pUser, int slot);                   // P96: запись ячейки сумки
// Статистика P100 (экспорт P100_GetStats — для стенда tools/stand_p100).
struct P100_Stats
{
    LONG codes, mergeCodes, keys;        // таблица: кодов, складываемых, ключей
    LONG merged;                         // выборов «стопка» на запросе
    LONG newCells;                       // новых ячеек ключа (резерв накопителя)
    LONG writesMerged;                   // записей в память, превращённых в «старое + добавка»
    LONG capHit;                         // потолок Cap (вид 154)
    LONG mismatch;                       // расхождений / исключений (вид 156)
    LONG rollbacks;                      // откатов аукциона вычитанием (вид 155)
    LONG weightFixed;                    // снятий веса слитой копии
    LONG pendAdded, pendReleased, pendExpired, pendDropped;   // накопитель
    LONG skippedReserved;                // ячеек, пропущенных стоковым роутером (резерв другого ключа)
    LONG chainFixed;                     // подстановок afterSlot (вызывающий записал слот стопки)
    LONG roomGranted;                    // ячеек, «добавленных» предпроверкам (сольётся)
    LONG echoSlots;                      // ячеек ответа 2604 из эха тела
    LONG chargesFixed;                   // чтений FT+13 с зарядами ≠ u8 стока (300 → 300, а не 44)
    LONG viaBox;                         // слияний позиций коробок (P95)
    LONG pendCancelled;                  // записей накопителя, снятых при отказе стока «нет места»
    LONG softReserved;                   // новых ячеек, взятых из зарезервированных (других свободных нет)
    LONG ledgerEvicted;                  // вытеснений из журнала добавок аукциона
    LONG movesRefused;                   // перемещений 5000 ячейки с зарядами в полёте — отказ 18
    LONG moveMarks;                      // ячеек, помеченных «перемещение в полёте»
    LONG opsRefused;                     // операций над ячейкой со слиянием в полёте — стоковый отказ (ревизия 02.11)
    LONG journaled, suppressed;          // журнал P53
    LONG echoNonKey;                     // ★ 05.11 (v61): ячеек ответа 2604 из эха для кодов БЕЗ ключа (EchoAllCodes)
    LONG echoBusy;                       // ★ 05.11 (v61): ячейка эха 2604 занята в памяти — стоковый выбор + вид 156
};
extern "C" __declspec(dllexport) void  __stdcall P100_GetStats(P100_Stats* out);
// ── общие точки P100 для P95 / P16 / P62 / P101 ──
extern "C" __declspec(dllexport) int   __stdcall P100_Active();                                         // 1 — площадки стоят
extern "C" __declspec(dllexport) int   __stdcall P100_SiteOn(int bit);                                  // бит Sites включён
extern "C" __declspec(dllexport) int   __stdcall P100_KeyOf(int code);                                  // ключ слияния (0 — нет)
extern "C" __declspec(dllexport) int   __stdcall P100_Charges(int code);                                // заряды выдачи i32 (−1 — сток)
extern "C" __declspec(dllexport) int   __stdcall P100_CountLotMerges(void* mgr, int userNum, const int* codes, const int* adds, int n, int site);   // ★ P102: лоты без новой ячейки
extern "C" __declspec(dllexport) DWORD __stdcall P100_BeginBatch();                                     // номер пакета выдачи
extern "C" __declspec(dllexport) int   __stdcall P100_FindChargeStack(void* mgr, int userNum, int code, int add, int site, int owner, DWORD batch, int* isNewOut);   // стопка ключа и Owner + накопитель; −1 — нет; owner −1 — по привязке
extern "C" __declspec(dllexport) void  __stdcall P100_ReserveNew(void* mgr, int userNum, int code, int add, int owner, int slot, DWORD batch);   // резерв новой ячейки первой копии (owner −1 — по привязке)
extern "C" __declspec(dllexport) int   __stdcall P100_IsReserved(void* mgr, int userNum, int slot, int key, int code);   // ячейка в резерве другого ключа/Owner
extern "C" __declspec(dllexport) void  __stdcall P100_CancelBatch(int userNum, DWORD batch);                                         // отказ до БД — снять пакет
extern "C" __declspec(dllexport) int   __stdcall P100_WriteMerged(void* mgr, int userNum, BYTE* rec, int wresp);                     // запись в память со слиянием
extern "C" __declspec(dllexport) int   __stdcall P100_IsBoxMergeSlot(int userNum, int slot);                                         // P62: общая ячейка коробки
extern "C" __declspec(dllexport) int   __stdcall P100_BoxPlace(void* mgr, int userNum, int code, int pos, DWORD batch);              // P95: стопка позиции коробки
extern "C" __declspec(dllexport) int   __stdcall P100_PremiumSlot(void* mgr, int userNum, int code, int container, int after, int add); // P16: ячейка копии
extern "C" int __stdcall P100_Call3(int id, BYTE* ebp, void* mgr, int a1, int a2, int a3);             // трамплины call-площадок
extern "C" int __stdcall P100_Call2(int id, BYTE* ebp, void* mgr, int a1, int a2);
extern "C" int __stdcall P100_Call5(int id, BYTE* ebp, void* mgr, int a1, int a2, int a3, int a4, int a5);   // sub_4D61E0 / sub_5646C0
extern "C" BOOL __stdcall P100_IsF(int id, BYTE* ebp, int code);                                         // крафт 0x53E4B8
extern "C" int __stdcall P100_ChargesAt(const BYTE* p);                                                 // [ИСПРАВЛЕНИЕ 300] чтение FT+13
extern "C" __declspec(dllexport) int __stdcall P100_GmGivePick(void* mgr, int userNum, int code);       // ★ P127 А2.3: ячейка F как площадка A4 0x5525B0
extern "C" void __stdcall P100_OnGacha(BYTE* ebp);                                                      // A2 5468: точка 0x4F4F7B

// ★ P101 — ПОДАРОК ИЗ КЭШ-МАГАЗИНА (02.11.2026, решение владельца; проект Reports/cash_gift/PROJECT_P101.md, итог
//   p101/DLL_DONE.md): отправляющая половина GS [ВОССТАНОВЛЕНА ПО КОНТРАКТУ] — 5072 → DB 2132, 5074 → 0x52 HOLD в GP7, 0x53 → 5076
//   в реле, 5077 → 0x52 COMMIT/REFUND и 5075; получатель — план раскладки со слиянием зарядов P100 (бит 8), [ИСПРАВЛЕНИЕ 300] FT+13
//   @0x5136DA. Таблица «в полёте» в DLL, тайм-аут без автовозврата. Журнал ac.other 158–163. [P101_CashGift] Enabled=0.
PatchResult P101_CashGift();
// Статистика P101 (экспорт P101_GetStats — для стенда tools/stand_p101).
struct P101_Stats
{
    LONG req5072, refused5072, sent2132, routes2133, badName, envelopeRefused, badLen;   // A
    LONG req5074, refused5074, holdSent, gp7Sent, gp7SendFail;                           // B
    LONG recv53, unknown53, holdOk, holdRefused, retries53, stuck, sent5076;             // C
    LONG recv5077, settleSent, settleOk, sent5075;                                       // E
    LONG recv5076, recvAbsent, recvPlaced, recvMerged, recvNoRoom, recvDbError, recvWritesMerged, recvPlanPicks;   // D
    LONG resent, timeouts;                                                                // F (фоновая нить)
    LONG faults, journaled;                                                               // исключения, строки журнала
    LONG pumpThreadId, inFlight, sites;                                                   // нить повторов, записей «в полёте», маска после коррекции
    LONG routesStale, echo53, recvGone2135;                                               // ревизия: 2133 не на последний 5072, эхо 0x53, 2135 без получателя
};
extern "C" __declspec(dllexport) void __stdcall P101_GetStats(P101_Stats* out);
extern "C" __declspec(dllexport) void __stdcall P101_Pump();                                            // один проход повторов/тайм-аутов (фоновая нить; стенд)
extern "C" int  __stdcall P101_OnClient(int opcode, BYTE* ebp, void* mgr, int userNum, BYTE* frame, int packetLen);   // стаб 0x42AD02
extern "C" void __stdcall P101_OnGateway(BYTE* ebp, void* mgr, BYTE* frame);                            // стаб 0x42FC62 (0x53)
extern "C" int  __fastcall P101_On2133(void* mgr, void* edx, int a2, BYTE* frame);                     // call @0x4303DE
extern "C" int  __fastcall P101_On5076(void* mgr, void* edx, int a2, BYTE* frame);                     // call @0x430412
extern "C" int  __fastcall P101_On5077(void* mgr, void* edx, int a2, BYTE* frame);                     // call @0x430446
extern "C" int  __fastcall P101_On2135(void* mgr, void* edx, int a2, BYTE* frame);                     // call @0x43047A
extern "C" int  __stdcall P101_RecvRoom(BYTE* ebp, void* mgr, int a1, int a2);                          // call @0x5134B3
extern "C" int  __stdcall P101_RecvPick(BYTE* ebp, void* mgr, int a1, int a2, int a3);                  // call @0x513558
extern "C" int  __stdcall P101_RecvWrite(BYTE* ebp, void* mgr, int a1, BYTE* rec, BYTE* src);           // call @0x513D31
extern "C" int  __stdcall P101_ChargesAt(const BYTE* p);                                                // @0x5136DA

// ★ P102 — [ИСПРАВЛЕНИЕ] ДЕФЕКТЫ ОРИГИНАЛА ВЫДАЧИ (02.11.2026, решение владельца; разбор Reports/item_dedup/charges, MEMANTO p102-dll):
//   (1) разборка 6502: спецпредмет (камни 401/363) выдавался с Amount 0 и весом мимо @Weight — теперь количество в БД = заряды
//       кода, вес — через @Weight (0x4FE76F); (2) книга рыбака 6182: в БД @Amount спецпредмета = заряды записи, а не количество
//       таблицы (0x41344C); (2в) ответ книги при ошибке БД больше не пишет пустую книгу поверх CUser (очки рыбалки) и не шлёт
//       второй 6183 «успех» (0x413598); (3) снятие лотов 9910 — предпроверка вместимости перед циклом (0x51EE6B), отказ стоковым
//       кодом ДО записи в память. Ошибка P100 v57 на аукционе (цепочка afterSlot) исправлена в самом P100 (R_B5BUYEQ/R_B5DELEQ).
//   (4) воскрешение 5450 (FT+8 = 48): отказ до БД, если персонаж жив или в целях есть лишний живой слот (0x4EDDE1) — сток
//       списывал заряд в БД и отказывал в ответе, память не уменьшалась (строки 205 с Amount 0).
//   Журнал ac.other 164–167. [P102_DefectFixes] Enabled=1, Sites (1 разборка, 2 книга-количество, 4 книга-ошибка БД, 8 9910, 16 воскрешение).
PatchResult P102_DefectFixes();
// Статистика P102 (экспорт P102_GetStats — для стенда tools/stand_p102).
struct P102_Stats
{
    LONG disasmFixed;     // разборка: спецпредмет выдан с зарядами
    LONG bookAmount;      // книга: @Amount спецпредмета = заряды
    LONG bookDbError;     // книга: ошибка БД — выход без записи в CUser
    LONG lotChecks;       // 9910: предпроверок
    LONG lotRefused;      // 9910: отказ до цикла (места нет)
    LONG reviveChecks;    // 5450: проверок воскрешения (FT+8 = 48)
    LONG reviveRefused;   // 5450: отказ до БД (жив / лишние цели)
    LONG faults;          // исключения (решение стока)
    LONG journaled;       // строк журнала
    LONG suppressed;      // подавлено ограничителем
};
extern "C" __declspec(dllexport) void __stdcall P102_GetStats(P102_Stats* out);
extern "C" int __stdcall P102_DisasmAdd(int code);   // P100 R_B9: добавка разборки = заряды кода, если стоит площадка P102 (иначе 0 — сток)

// ★ P103 — [ИСПРАВЛЕНИЕ] «В ПОЛЁТЕ» (04.11.2026, AsdaPatch v60; разбор Reports/item_dedup/p103/P103_REPORT.md):
//   S1 коробка 6096: ответ 2273 с отказом БД (Flag 0) в память не пишет — записи накопителя P100 жили 60 с (перемещение ячеек отказано,
//      вид 156); теперь снимаются по эху записей (0x55B251, P100_ReleaseRecs). S2 5450: второй запрос той же группы отката FT+38 (и того же
//      кода при FT+18 > 0) до ответа 2141 на первый — отказ до БД кодом 12 / 8 (сток: заряд списан в БД, ответ отказывал «CoolTime Not
//      Spend»). S3 автоприменение 2223/2224 — тот же замок группы. Журнал ac.other 168–170. [P103_InFlightFixes] Enabled=1, Sites 7.
PatchResult P103_InFlightFixes();
struct P103_Stats
{
    LONG boxReplies;      // S1: ответов 2273 с живым CUser
    LONG boxRefused;      // S1: из них отказ БД (Flag ≠ 1) при стоящем P100
    LONG boxReleased;     // S1: снято записей накопителя P100
    LONG gateChecks;      // S2: проверок на входе LABEL_69
    LONG refusedGroup;    // S2: отказ 12 — группа в полёте
    LONG refusedCode;     // S2: отказ 8 — код в полёте
    LONG refusedAuto;     // S3: автоприменение — группа в полёте
    LONG latchSet;        // замков поставлено
    LONG latchCleared;    // снято ответом
    LONG latchExpired;    // снято по LatchTtlMs
    LONG faults;          // исключения (решение стока)
    LONG journaled;       // строк журнала
    LONG suppressed;      // подавлено ограничителем
    LONG sendFailed;      // уход 2140/2223 не удался (sub_5646C0 = 0) — замок не ставился
};
extern "C" __declspec(dllexport) void __stdcall P103_GetStats(P103_Stats* out);
extern "C" void __stdcall P103_OnDbSent(int op, const BYTE* body, int userNum);   // уход 2140 / 2223 в БД (P100 G_AUTOUSE зовёт после своей отправки)
extern "C" __declspec(dllexport) int __stdcall P100_ReleaseRecs(void* mgr, int userNum, const BYTE* recs, int n, int stride, int* slotsOut);   // P103 S1
const void* P75_DbSendStub();                // стаб P75 площадки 0x4EF02E, если P75 поставлен; иначе nullptr
DWORD       P75_ChainDbSend(DWORD next);     // подставить «следующий вызов» стаба P75 (возврат — прежний)

// ★ P106 — [ИСПРАВЛЕНИЕ] ПРИНЯВШИЙ ДРУЖБУ ПОЛУЧАЕТ 4151 ПРИ ФЛАГЕ 2 UPFriendAdd (05.11.2026, AsdaPatch v63, сессия friend-accept;
//   документ AstoryServer/Docs/GameServer/friend-accept-notify-p106.md): ответ 2216 sub_406370 слал 4151 код 1 принявшему только при
//   флаге 1 и 3; при 2 (у пригласившего уже был принявший — вставлена строка принявшего) тот не узнавал. Участок 0x406520 (22 б):
//   условие «флаг 1…3». [P106_FriendAcceptNotify] Enabled=1.
PatchResult P106_FriendAcceptNotify();       // 4151 принявшему дружбу при флаге 1…3, 2026-11-05

// ★ P107 — [ИСПРАВЛЕНИЕ] ОГЛУШЁННЫЙ НЕ АТАКУЕТ И НЕ ПРИМЕНЯЕТ НАВЫКИ (05.11.2026, AsdaPatch v64, сессия stun-attack; отчёт
//   AstoryServer/Docs/GameServer/cant-act-gate-p107.md): общий гейт sub_484E40 (4026/4028/5256/4201/4203) при оглушении 3 и страхе 4 всегда
//   пропускал (задумано — только навыки 736/984), «Мощное оглушение» 14 не проверял. Участки 0x484EBB (38 б), 0x484EEF (36 б),
//   0x484F4D (2 б). [P107_CantActGate] Enabled=1.
PatchResult P107_CantActGate();              // гейт «не может действовать»: 3/4 — только 736/984, 14 — нельзя, 2026-11-05

// ★ P108 — [ИСПРАВЛЕНИЕ] ПОВТОРНЫЙ ВХОД ИЗ ДАНЖА — В ТОЧКУ ВХОДА (05.11.2026, AsdaPatch v65, сессия dungeon-relog; документ
//   AstoryServer/Docs/GameServer/dungeon-relog-entry-p108.md): выход/обрыв/закрытие клиента (DisConnectUser, пакет 2003 →
//   UPLogoutGame) сохранял в данже (атрибут MapInfo 3) клетку как есть — повторный вход в ту же точку. Площадка 0x5257A0 (10 б):
//   карты EntryMaps (8, 9, 17) — первая точка старта MapInfo; турнирные ReturnMaps (10, 11) — назначение и STARTPOS первого
//   портала своей карты. [P108_DungeonRelogEntry] Enabled=1.
PatchResult P108_DungeonRelogEntry();        // выход из данжа сохраняется в точку входа, 2026-11-05
extern "C" __declspec(dllexport) void __stdcall P108_Decide(BYTE* ebp);     // C-часть трамплина (экспорт — для стенда)
extern "C" __declspec(dllexport) void __stdcall P108_GetStats(int* out);    // счётчики: вызовы, вход, возврат, нет точки, исключения

// ★ P109 — [ИСПРАВЛЕНИЕ] НАВЫК «НА СЕБЯ» НЕ БЬЁТ КАСТЕРА (05.11.2026, AsdaPatch v66, сессия job4-skills): NpcServer считал урон
//   по записи цели «сам кастер» (611 Parry / 612 King's Rage / 616 Violent Storm — множитель ms > 0), GameServer sub_471C70 вычитал
//   его из HP кастера, 5257 нёс его клиенту. Вход sub_470DB0 (ответ 8206) @0x470DB0 9 б: у таких записей урон 0, флаги & 0x03.
//   [P109_SelfHitNoDamage] Enabled=1.
PatchResult P109_SelfHitNoDamage();          // само-каст без урона по себе, 2026-11-05
extern "C" __declspec(dllexport) void __stdcall P109_Filter(int userNum, BYTE* pkt);   // C-часть трамплина (экспорт — для стенда)
extern "C" __declspec(dllexport) void __stdcall P109_GetStats(int* out);              // счётчики: входы, обнулено, плохая длина, исключения

// ★ P110 — [ИСПРАВЛЕНИЕ] ДВА ПУЛА ОЧКОВ НАВЫКОВ (05.11.2026, AsdaPatch v67, сессия job4-points; документ
//   AstoryServer/Docs/GameServer/job4-point-pools-p110.md): Recv_SkillPoint_SkillActive (5253) сверял только общий счёт очков —
//   навык 4-й профессии (деревья 10/11/12) брал очки основных деревьев (лимит 110), основной — очки 4-й профессии. Площадка
//   0x4778B3 (14 б): остаток пула навыка < числа → 5254 код 8 (111701) / 3 (2202). [P110_Job4PointPools] Enabled=1.
PatchResult P110_Job4PointPools();           // пулы очков: основные ≤ 110, 4-я профессия — сверх 110 с 60-го уровня, 2026-11-05
struct P110_Stats
{
    LONG seen;          // вызовов площадки (запросов, прошедших отказы стока)
    LONG job4Seen;      // из них — навык дерева 4-й профессии
    LONG mainSeen;      // из них — навык основного дерева
    LONG refusedJob4;   // отказ: пул 4-й профессии
    LONG refusedMain;   // отказ: основной пул
    LONG exempt;        // пропущено по ExemptMaxUserIndex
    LONG faults;        // исключения (решение стока)
    LONG journaled;     // строк журнала
    LONG suppressed;    // подавлено ограничителем
};
extern "C" int __stdcall P110_Check(BYTE* user, int skill, int count, int points, int userNum);   // C-часть трамплина
extern "C" __declspec(dllexport) void __stdcall P110_GetStats(P110_Stats* out);                 // счётчики

// ★ P111 — [ИСПРАВЛЕНИЕ] ДОБАВКА ВЫЛУПЛЕНИЯ ДАЁТ ОБЕЩАННЫЕ +30% (05.11.2026, AsdaPatch v68, сессия pet-hatch-summon; документ
//   AstoryServer/Docs/GameServer/hatch-supplement-p111.md): Recv_IncubatorReq (6102) прибавлял значение добавки 298/322 (30) к шансу в
//   стотысячных — +0,03 п.п.; подтип слота 3 не сверялся. Площадка 0x4556C3 (6 б): значение × 1000, чужой подтип → 6103 код 5.
PatchResult P111_HatchSupplement();          // добавка вылупления: значение × SupplementScale, в слот 3 — только подтип 108, 2026-11-05
struct P111_Stats
{
    LONG seen;            // вызовов площадки (запросов, дошедших до формулы)
    LONG withItem;        // из них — с предметом в слоте 3
    LONG scaled;          // значение добавки умножено
    LONG refusedSubType;  // отказ: чужой подтип в слоте 3 (Mode=0 — только счёт)
    LONG faults;          // исключения (решение стока)
    LONG journaled;       // строк журнала
    LONG suppressed;      // подавлено ограничителем
};
extern "C" int __stdcall P111_Apply(BYTE* user, int code, int* value, int base, int catalyst, int userNum);   // C-часть трамплина
extern "C" __declspec(dllexport) void __stdcall P111_GetStats(P111_Stats* out);                 // счётчики

// ★ P112 — [ИСПРАВЛЕНИЕ] РАЗБРОС УРОВНЕЙ ОТРЯДА В ОПЫТЕ (06.11.2026, AsdaPatch v69, сессия pet-hatch-summon; документ
//   AstoryServer/Docs/GameServer/party-exp-spread-p112.md): sub_4C7650 считал разброс только по записям 8306 и с минимумом от 59.
//   Площадка 0x4C7A8E (12 б): весь отряд, настоящий минимум.
PatchResult P112_PartyExpSpread();           // разброс уровней отряда в опыте: весь отряд, настоящий минимум, 2026-11-06
struct P112_Stats
{
    LONG seen;       // вызовов площадки (пакетов 8306)
    LONG blocked;    // сток дал бы опыт, разброс отряда запретил
    LONG unlocked;   // сток запретил из-за константы 59, разрешено
    LONG faults;     // исключения (решение стока)
    LONG journaled;  // строк журнала
    LONG suppressed; // подавлено ограничителем
};
extern "C" int __stdcall P112_Decide(void* mgr, const short* pkt, int hiStock, int loStock);   // C-часть трамплина
extern "C" __declspec(dllexport) void __stdcall P112_GetStats(P112_Stats* out);                // счётчики

// ★ P114 — [ИСПРАВЛЕНИЕ] ОПЫТ ЗАДАНИЙ ДОСКИ УСИЛИВАЕТСЯ, КАК ОПЫТ ОБЫЧНОГО ЗАДАНИЯ (07.11.2026, AsdaPatch v71, пачка 11, баг 8,
//   AstoryServer/Docs/GameServer/board-exp-bonus-p114.md): recvDBLimitationResult звал начисление мимо GetExpUpDownValue. Площадка 0x53C4F9 (5 б).
PatchResult P114_BoardExpBonus();            // опыт заданий доски через GetExpUpDownValue
struct P114_Stats
{
    LONG seen;       // вызовов площадки (начислений опыта доски)
    LONG boosted;    // опыт изменён усилениями
    LONG faults;     // исключения (опыт стока)
};
extern "C" void __stdcall P114_Adjust(void* mgr, DWORD* args);                                  // C-часть трамплина
extern "C" __declspec(dllexport) void __stdcall P114_GetStats(P114_Stats* out);                 // счётчики

// ★ P117 — [ИСПРАВЛЕНИЕ] ЗЕЛЬЕ УРОВНЯ НЕ ПРИМЕНЯЕТСЯ, ПОКА ДЕЙСТВУЕТ ПРЕЖНЕЕ (09.11.2026, AsdaPatch v72, пачка 19, баг 9,
//   AstoryServer/Docs/GameServer/plus-pack-once-p117.md): case 120 Char_FunctionItem_Use при CUser+0xBFC7 > 0 — 5451 код 0x10. Площадка 0x4EE25B (6 б).
PatchResult P117_PlusPackOnce();             // повтор набора уровня при действующем — отказ 5451 0x10, предмет цел
struct P117_Stats
{
    LONG seen;       // заходов в case 120 (применений набора уровня)
    LONG refused;    // отказов: набор ещё действует
    LONG faults;     // исключения (решение стока)
};
extern "C" int __stdcall P117_Gate(BYTE* ebp);                                                  // C-часть заглушки
extern "C" __declspec(dllexport) void __stdcall P117_GetStats(P117_Stats* out);                 // счётчики

// ★ P120 — ПЕРЕХОД В ШАХТУ (карта 23) И ОБРАТНО (09.11.2026, AsdaPatch v73, пачка 20, AstoryServer/Docs/GameServer/mine-travel-p120.md):
//   тип карты 6 получает поток и вход (площадки 0x4A53DC, 0x4A84BC, 0x4A72BE, 0x4C0BE5, 0x52D38E), приём 6746/6749 (0x42AE1B) → 5055.
PatchResult P120_MineTravel();               // кнопки NPC 181 «Шахта» и стражей 202/203/204 «В Альпию» ведут на карту
struct P120_Stats
{
    LONG seen;       // пакетов 6746/6749
    LONG entered;    // переходов в шахту (5055 код 1)
    LONG exited;     // переходов из шахты
    LONG refused;    // отказов (не та карта, нет NPC рядом, карта закрыта, чужой charId)
    LONG envelope;   // отказ конверта (анти-повтор / MD5)
    LONG badLength;  // короткий кадр
    LONG faults;     // исключения (пакет проигнорирован)
};
extern "C" int __stdcall P120_OnClient(int opRel, BYTE* mgr, int userNum, BYTE* frame, int packetLen);   // C-часть стаба диспетчера
extern "C" __declspec(dllexport) void __stdcall P120_GetStats(P120_Stats* out);                 // счётчики

// ★ P118 — [ИСПРАВЛЕНИЕ] ОБМЕН ОТМЕНЯЕТСЯ, ПОКА ИГРОК РАБОТАЕТ С АУКЦИОНОМ (09.11.2026, пачка 20, баг 3, жалоба 10,
//   AstoryServer/Docs/GameServer/auction-trade-block-p118.md): метка в прологах 9901/9903/9905/9907/9909; 5282 (0x4DFA09) → 5283 коды 5/4,
//   5284 (0x4DFE27) → 5285 код 0 обеим; StormGuard (0x51A9D6, выкл) — пустой 9908 заменяется записью со статусом 3.
PatchResult P118_AuctionTradeBlock();        // заявка/согласие обмена при свежей метке аукциона — штатный отказ
struct P118_Stats
{
    LONG marked;      // меток «работает с аукционом» (заходов в пять обработчиков)
    LONG tableFull;   // метка не записана: 64 пробы заняты свежими метками
    LONG reqSeen;     // проверок 5282
    LONG reqSelf;     // отказов 5282 кодом 5 (заявитель на аукционе)
    LONG reqTarget;   // отказов 5282 кодом 4 (цель на аукционе)
    LONG accSeen;     // проверок 5284 (согласие)
    LONG accRefused;  // отказов 5284 (5285 код 0 обеим)
    LONG storm;       // пустых 9908, заменённых записью (StormGuard)
    LONG faults;      // исключения (решение стока)
};
extern "C" void __stdcall P118_Touch(int op, void* mgr, int num);                               // A: метка из пролога
extern "C" int __stdcall P118_ReqGate(BYTE* ebp);                                               // B: 5282
extern "C" int __stdcall P118_AccGate(BYTE* ebp);                                               // C: 5284
extern "C" __declspec(dllexport) void __stdcall P118_GetStats(P118_Stats* out);                 // счётчики

// ★ P121 — [ИСПРАВЛЕНИЕ] ПРЕДМЕТ СМЕНЫ ИМЕНИ НЕ ТРАТИТСЯ ЧЕРЕЗ 5450 (09.11.2026, AsdaPatch v75, пачка 20, баг 8,
//   AstoryServer/Docs/GameServer/char-rename-guard-p121.md): Char_FunctionItem_Use, категория 111 — 5451 код 0 до БД. Площадка 0x4EDEB3 (6 б).
PatchResult P121_CharRenameGuard();          // 5450 с предметом смены имени — отказ 5451, предмет цел (смена имени — 6138/6140)
struct P121_Stats
{
    LONG seen;       // заходов в switch по категории (5450 до ветвления)
    LONG refused;    // отказов: категория 111 через 5450
    LONG faults;     // исключения (решение стока)
};
extern "C" int __stdcall P121_Gate(BYTE* ebp, int cat);                                        // C-часть заглушки
extern "C" __declspec(dllexport) void __stdcall P121_GetStats(P121_Stats* out);                 // счётчики

// ★ P122 — ФУНКЦИЯ ПИТОМЦА НЕ НИЖЕ ТАБЛИЦЫ (09.11.2026, AsdaPatch v76, пачка 20, баг 4, решение владельца «Не ниже таблицы»;
//   AstoryServer/Docs/GameServer/pet-func-floor-p122.md): sub_459AD0 пишет max(расчёт по уровню и сытости, PetInfo). Площадка 0x459C0E (7 б).
PatchResult P122_PetFuncFloor();             // функция питомца не ниже значения PetInfo_Table
struct P122_Stats
{
    LONG seen;       // записей функций (3 на каждый пересчёт питомца)
    LONG raised;     // поднято до значения таблицы
    LONG faults;     // исключения (решение стока)
};
extern "C" int __stdcall P122_Floor(BYTE* ebp, int value);                                      // C-часть заглушки
extern "C" __declspec(dllexport) void __stdcall P122_GetStats(P122_Stats* out);                 // счётчики

// ★ P123 — GM-ПРЫЖОК НА ДРУГУЮ КАРТУ ПО КЛЕТКЕ (09.11.2026, AsdaPatch v77, пачка 20, решение владельца «Да, P123»;
//   AstoryServer/Docs/GameServer/gm-map-jump-p123.md): 6010 с телом 8 б (X, Z, карта, метка A123) → 5055 код 1. Площадка 0x54EF50 (9 б пролога).
PatchResult P123_GmMapJump();                // GM-прыжок на другую карту по клетке (6010, тело 8 б с меткой)
struct P123_Stats
{
    LONG seen;         // кадров 6010 формы P123 (тело 8 б, метка A123)
    LONG jumped;       // ушло 5055 код 1
    LONG refused;      // отказов (та же карта, очередь, тип/закрыта/нет потока карты, клетка вне карты или непроходима)
    LONG notOperator;  // не оператор или нет GM-флага
    LONG envelope;     // отказ конверта (анти-повтор / MD5)
    LONG faults;       // исключения (кадр проигнорирован)
};
extern "C" int __stdcall P123_OnJump(BYTE* mgr, int userNum, BYTE* frame);                      // C-часть заглушки
extern "C" __declspec(dllexport) void __stdcall P123_GetStats(P123_Stats* out);                 // счётчики
// ★ P123 + P127 (18.11.2026): общая точка «перенос на другую карту по клетке» (проверки P123 + 5055 код 1). Нить карты игрока.
//   1 — 5055 отправлен (why = "ok"), 0 — отказ (why — причина по-английски, как в Log_Operator P123).
int P123_PortalMoveTo(BYTE* mgr, int userNum, int dest, int x, int z, const char** why);
bool P123_Applied();                          // P123 установлен (опоры MoveCore сверены) — гейт переноса P127
// ★ P127 А2.2 (18.11.2026): общие точки «живьём» для моста админ-центра (нить карты игрока).
bool    P75_Applied();                     // P75 поставлен (адреса опыта сверены)
bool    P75_ExpAt(int lvl, __int64* out);  // ExpTable[lvl] — накопленный опыт начала уровня
int     P75_CapLevel();                    // потолок уровня (imm8 0x4CBB63, P29)
int     P75_LevelOf(void* mgr, int num);   // уровень по памяти (0x5325F0)
__int64 P75_ExpOf(void* mgr, int num);     // опыт по памяти (0x4CABC0)
int     P75_GrantTo(void* mgr, int num, __int64 target, int maxCalls, int* lvl1, __int64* exp1, int* sk4036, int* skJar, int* fallback);   // опыт событиями стока (0x4CBA90) с ключами P75
bool    P75_ExpTableGrows(int lvl, __int64 target);   // ExpTable растёт от lvl до порога выше target (проверка 4 зелья)
bool    P24_Applied();                     // P24 поставлен
int     P24_FameCount();                   // число званий FameInfo
void    P24_RevokeTitle(void* mgr, void* pUser, int userNum, int titleId);   // снятие звания с доводкой (как у рейтинговых)
bool    P25_Applied();                     // P25 поставлен
int     P25_RecalcUser(void* mgr, int userNum, int* checked, int* skipped);  // пересчёт №3 одному игроку; −1 — нельзя
int     P25_RunRecalc(void* mgr, int userNum, int what, int* outA, int* outB);  // ★ А5.4: шаги 6–8 команды 6020 от имени оператора; −1 — нельзя

// ★ P127 — МОСТ АДМИН-ЦЕНТРА (волна А2 «живой канал», 18.11.2026; разбор Reports/admin_center/research_admin_bridge.md,
//   документ AstoryServer/Docs/GameServer/admin-bridge-p127.md). Фоновая нить: своё ODBC к AsdaAdmin (логин asda_bridge — только
//   EXECUTE adm.Bridge*), пульс узла, присутствие «кто в игре», захват команд (HMAC-SHA256, не больше одного раза). Выполнение — в нити
//   карты игрока на общей точке UserTick (0x526CEB, стаб P73). Mode=0 — только слушать (присутствие и ping; прочее — итог «журнал»).
PatchResult P127_AdminBridge();
// ★ P128 (А5.10, 21.11.2026): значок события Event.dat (6039/6041) всем игрокам в мире — такт игрока (общая точка UserTick P73).
PatchResult P128_EventBadgeAll();
extern "C" void __stdcall P128_OnUserTick(void* mgr, int userNum, BYTE* user);   // из P73_OnCheckUser (UserTick)
extern "C" void __stdcall P128_OnConnFlag(int slot, int flag);                    // из P73_OnConnFlag (разрыв / новое соединение)
bool P128_Applied();
// ★ P129 (А6.12, 22.11.2026): журнал и заглушка чата (AstoryServer/Docs/GameServer/chat-log-p129.md). Точка — общий гейт P47
//   (P47_OperatorGate зовёт P129_ChatGate ЧЕТВЁРТЫМ, после P55/P64/P69; 0 — обработчик не вызывать) и площадки крика предметом.
//   P129_GateWanted — P47 ставит стаб 0x42AB4F и при OperatorGmFlag=0, если P129 включён (читает ini сам).
PatchResult P129_ChatLog();
bool P129_GateWanted();
int  P129_ChatGate(void* mgr, int opcode, int userNum, const BYTE* pkt);
bool P129_ShoutGateWanted();               // P121 ставит площадку 0x4EDEB3 и при Enabled=0, если P129 включён с ShoutItemHook
extern "C" int __stdcall P129_ShoutRequestGate(BYTE* ebp);   // из P121_Gate (категории 0x31/0x32): 1 — отказ до расхода (заглушка, Mode=1)
extern "C" void __stdcall P127_OnLogon(int kind, int userNum, BYTE* user, int userIndex);   // из P73_OnLogon (общая точка входа)
extern "C" void __stdcall P127_OnConnFlag(int slot, int flag);                               // из P73_OnConnFlag (общая точка разрыва)
extern "C" int  __stdcall P127_OnUserTick(void* mgr, int userNum, BYTE* user);              // из P73_OnCheckUser (UserTick): 1 — выведен
int  P127_KickInProgress();                 // в этой нити идёт кик P127: 0/1 (P48 — «не засчитан» 8, P58 — «AdminBridge(P127)»)
bool P73_UserTickInstall();                 // поставить общую точку UserTick 0x526CEB (если её ещё нет); true — стоит
bool P73_EventsHooked();                    // события входа/разрыва доходят до P73_OnLogon/P73_OnConnFlag
struct P127_Stats
{
    LONG logons, logouts;       // события слотов
    LONG snapshots;             // снимков присутствия (изменений)
    LONG claimed;               // команд захвачено
    LONG done, refused, absent, journal;   // итоги 2 / 3 / 4 / 6
    LONG macBad;                // подпись не сошлась
    LONG kicks, pings, notices, moves;     // выполнено по видам
    LONG dbConnects, dbErrors;  // подключений к базе / ошибок SQL
    LONG resultsSent, presenceSent;        // строк в базу
    LONG faults;                // исключений при выполнении (поймано)
    LONG gives;                 // ★ А2.3: выдач предмета (команд give с итогом 2)
};
extern "C" __declspec(dllexport) void __stdcall P127_GetStats(P127_Stats* out);
