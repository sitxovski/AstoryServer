// Copyright (c) 2026 @sitxovski (Discord)
// Hook.h — примитивы правки кода хост-процесса.
// Правило: НИ ОДИН патч не пишет байты, не сверив предварительно оригинал.
#pragma once
#include <windows.h>

namespace Hook
{
    // Снятие/возврат защиты страниц на время записи.
    class Unlock
    {
    public:
        Unlock(void* addr, SIZE_T size);
        ~Unlock();
        bool Ok() const { return m_ok; }
    private:
        void*  m_addr;
        SIZE_T m_size;
        DWORD  m_old;
        bool   m_ok;
    };

    // Сверка оригинальных байтов по VA. false — несовпадение (патч ставить нельзя).
    bool Verify(DWORD va, const BYTE* expect, SIZE_T len);

    // Запись сырых байтов (с Unlock внутри).
    bool WriteBytes(DWORD va, const BYTE* data, SIZE_T len);

    // jmp rel32 на target + добивка nop'ами до siteLen (siteLen >= 5).
    bool WriteJmp(DWORD va, const void* target, SIZE_T siteLen);

    // call rel32 на target + добивка nop'ами до siteLen (siteLen >= 5).
    bool WriteCall(DWORD va, const void* target, SIZE_T siteLen);

    // Однобайтовая замена (перевороты ветвлений) со сверкой.
    bool WriteByteChecked(DWORD va, BYTE expect, BYTE value);

    // Hex-дамп для лога: "8b 4d f4 33 cd". out — минимум len*3+1 символов.
    void Dump(DWORD va, SIZE_T len, wchar_t* out, int cch);
}

// ── Утилита описания патч-площадки ──────────────────────────────────────────
// Используется всеми патчами: единый формат сверки и сообщений в логе.
struct Site
{
    DWORD       va;
    const BYTE* orig;
    SIZE_T      len;
};

// Сверяет все площадки патча. Пишет в лог результат по каждой.
// false — хотя бы одна не совпала (патч НЕ ставится).
bool VerifyAllSites(const wchar_t* patchName, const Site* sites, int count);
