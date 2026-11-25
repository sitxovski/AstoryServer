// Copyright (c) 2026 @sitxovski (Discord)
// Health.h — общие между нитями признаки исправности (ред. 3 контракта §8.3, E1-09): AsdaId (свои нити) сообщает ядру
// сайдкара (нить EOS), что выдача токенов деградировала (доля 503 за окно), — ядро включает FailOpen.
// Только атомарные поля: ядро читает, AsdaId пишет; блокировок между подсистемами нет.
#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <utility>

namespace Eac
{
    struct Health
    {
        std::atomic<int64_t> idDegradedUntil{ 0 };   // NowMs(), до которого AsdaId считается деградировавшим (0 — исправен)
        std::atomic<int>     idDegradedPct{ 0 };     // последняя замеренная доля 503, % (журнал)

        // ★ Д3 (22.11.2026, разбор eac_mode1_kick_decisions_20261122.md): AsdaId выдал /token или /refresh учётке — (NowMs, UserIndex).
        //   Ядро забирает раз за обслуживание (≤ 4 раза в секунду) и помнит последний токен учётки: ★ ревизия 64 — только для поблажки
        //   ОДНОЙ учётке с историей EAC (Core.cpp ConnectGrace), общего признака нет. Замок короткий (push / swap), предел очереди — 10 000.
        std::mutex tokMu;                                    // охраняет tok
        std::deque<std::pair<int64_t, uint32_t>> tok;        // выдачи с прошлого забора
        void NoteToken(int64_t nowMs, uint32_t ui)
        {
            std::lock_guard<std::mutex> lk(tokMu);
            if (tok.size() < 10000) tok.emplace_back(nowMs, ui);
        }
        std::deque<std::pair<int64_t, uint32_t>> TakeTokens()
        {
            std::deque<std::pair<int64_t, uint32_t>> out;
            std::lock_guard<std::mutex> lk(tokMu);
            out.swap(tok);
            return out;
        }
    };

    // Единственный экземпляр на процесс.
    inline Health& GetHealth() { static Health h; return h; }
}
