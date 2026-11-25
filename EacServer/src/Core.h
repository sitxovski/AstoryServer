// Copyright (c) 2026 @sitxovski (Discord)
// Core.h — ядро AsdaEacServer: сайдкар 15901 (AsdaSecure + кадры §3), мост 127.0.0.1:15702 (§4), таблица привязок
// «учётка (UserIndex) ↔ EAC-сессия ↔ (serverKind, pid, userNum) ↔ IP» и политика кика (§5–§6).
//
// ★ Модель потоков — ОДНА нить (WSAPoll + EOS_Platform_Tick каждые TickMs), без IOCP и без отдельной нити моста. Обоснование:
//   1) EOS SDK требует вызовов из одной нити (образец Samples/AntiCheat/Server: Transport.Update + Tick в одном цикле);
//      при IOCP всё равно пришлось бы передавать каждое сообщение в нить EOS через очередь;
//   2) нагрузка мала: несколько сотен соединений, сообщения EAC ≤ 512 байт по несколько в секунду, PING раз в 10 с;
//      WSAPoll по ~1000 сокетам за итерацию — микросекунды; рукопожатие AsdaSecure ~2 мс CPU, а с кэшем подписи и
//      пулом эфемерных пар (ServerSignerLoad / EphemeralPoolStart из sec2) — доли мс;
//   3) таблица привязок и политика без блокировок — их трогает только эта нить;
//   4) ред. 3 (E1-04): живучесть под шквалом соединений обеспечена не нитями, а порядком и пределами одного прохода —
//      сначала мост 15702 и зарегистрированные соединения, затем прочие, слушатели последними; не больше AcceptPerPass
//      accept за проход; token bucket на IP и общий; отказы — без строки журнала на каждый (сводка раз в RejectSummarySec).
//      Вынос моста в свою нить потребовал бы блокировок на таблице игровых сессий, которую политика читает из нити EOS
//      (KICK формируется по колбэкам EOS), — выигрыша нет, раз проход ядра и так ограничен по времени.
//   AsdaId (HTTP) живёт в своих нитях: там блокирующий ODBC, а с ядром у него общего состояния нет.
#pragma once
#include "Config.h"
#include "EosLayer.h"
#include "AsdaSecure.h"
#include <atomic>
#include <memory>
#include <string>

namespace Eac
{
    namespace AdminStatus { class Board; }   // ★ А6.8: AdminStatus.h

    class Core
    {
    public:
        Core(const Config& cfg, IEos* eos, const AsdaSecure::PrivateKey* secureKey);
        ~Core();
        // Открыть слушатели 15901 и 15702. false — порт занят и т.п.
        bool Start(std::string* err);
        // Главный цикл до stop == true.
        void Run(std::atomic<bool>& stop);
        // ★ А6.8 (22.11.2026): доска снимков точки статуса для панели (AdminStatus.h); вызывать до Run. nullptr (по умолчанию) —
        //   ядро снимков не строит и истории событий учёток не ведёт (поведение до А6.8).
        void SetStatusBoard(AdminStatus::Board* board);

    private:
        struct Impl;
        Impl* m;
    };

    // Коды причин (контракт §5).
    enum OurReason : uint8_t
    {
        kReasonNoSession   = 1,   // нет EAC-сессии у учётки за BindTimeoutSec
        kReasonEacAction   = 2,   // ClientActionRequired
        kReasonChannelLost = 3,   // канал 15901 потерян дольше GraceSec при живой игре
        kReasonRegRejected = 4,   // токен/регистрация отклонены
        kReasonEvicted     = 5,   // вытеснен новой EAC-сессией той же учётки
        kReasonNotBound    = 6,   // ред. 3 §8.1: игровое соединение не привязано к EAC-сессии (нулевой/чужой bind, BIND не пришёл, IP)
    };

    // Типы кадров (контракт §3 и §4).
    enum FrameType : uint8_t
    {
        kSideReg = 0x01, kSideRegResult = 0x81, kSideAcMsg = 0x02, kSideKick = 0x03, kSidePing = 0x04, kSidePong = 0x84,
        kSideBind = 0x05, kSideBindResult = 0x85,   // ред. 3 §8.1: привязка к игровому каналу (u8 serverKind · u8[32] bind) / u8 status
        kBrHello = 0x10, kBrLogin = 0x11, kBrLogout = 0x12, kBrRebind = 0x13, kBrPing = 0x14, kBrKick = 0x21, kBrPong = 0x24,
    };

    // Статусы REG_RESULT (§3).
    enum RegStatus : uint8_t { kRegOk = 0, kRegBadToken = 1, kRegAccount = 2, kRegInternal = 3, kRegDisabled = 4 };

    // Статусы BIND_RESULT (ред. 3 §8.1).
    enum BindStatus : uint8_t { kBindOk = 0, kBindRejected = 2 };

    constexpr size_t kBindLen     = 32;     // длина привязки игрового канала (HKDF-Expand(prk, "AsdaEacBind/v1", 32))
    constexpr uint8_t kBridgeVer  = 2;      // ред. 3: версия протокола моста (HELLO ver=2, LOGIN/REBIND с bind)
    constexpr size_t kMaxFrameLen = 4096;   // предел u16 len кадра
    constexpr size_t kMaxAcMsg    = 512;    // предел ACMSG (EOS_ANTICHEATSERVER_ONMESSAGETOCLIENTCALLBACK_MAX_MESSAGE_SIZE)
}
