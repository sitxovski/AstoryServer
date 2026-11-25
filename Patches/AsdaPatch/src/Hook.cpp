// Copyright (c) 2026 @sitxovski (Discord)
#include "Hook.h"
#include "Log.h"

namespace Hook
{
    Unlock::Unlock(void* addr, SIZE_T size)
        : m_addr(addr), m_size(size), m_old(0), m_ok(false)
    {
        m_ok = VirtualProtect(m_addr, m_size, PAGE_EXECUTE_READWRITE, &m_old) != FALSE;
    }

    Unlock::~Unlock()
    {
        if (m_ok)
        {
            DWORD tmp = 0;
            VirtualProtect(m_addr, m_size, m_old, &tmp);
            FlushInstructionCache(GetCurrentProcess(), m_addr, m_size);
        }
    }

    bool Verify(DWORD va, const BYTE* expect, SIZE_T len)
    {
        const BYTE* p = (const BYTE*)va;
        __try
        {
            for (SIZE_T i = 0; i < len; ++i)
            {
                if (p[i] != expect[i]) { return false; }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return true;
    }

    bool WriteBytes(DWORD va, const BYTE* data, SIZE_T len)
    {
        Unlock u((void*)va, len);
        if (!u.Ok()) { return false; }
        BYTE* p = (BYTE*)va;
        for (SIZE_T i = 0; i < len; ++i) { p[i] = data[i]; }
        return true;
    }

    static bool WriteRel32(DWORD va, BYTE opcode, const void* target, SIZE_T siteLen)
    {
        if (siteLen < 5) { return false; }
        // ★ 30.08.2026: буфер поднят 32 → 128. Площадка P24 @0x54D86F — 60 байт
        //   (два блока «выход из пакета» подряд), при 32 WriteJmp молча возвращал
        //   false и патч уходил в Failed. Размер ограничивает ТОЛЬКО длину
        //   затираемой площадки; на уже существующие патчи не влияет.
        BYTE buf[128];
        if (siteLen > sizeof(buf)) { return false; }
        const INT32 rel = (INT32)((DWORD)target - (va + 5));
        buf[0] = opcode;
        buf[1] = (BYTE)(rel        & 0xFF);
        buf[2] = (BYTE)((rel >> 8) & 0xFF);
        buf[3] = (BYTE)((rel >> 16) & 0xFF);
        buf[4] = (BYTE)((rel >> 24) & 0xFF);
        for (SIZE_T i = 5; i < siteLen; ++i) { buf[i] = 0x90; }
        return WriteBytes(va, buf, siteLen);
    }

    bool WriteJmp (DWORD va, const void* target, SIZE_T siteLen) { return WriteRel32(va, 0xE9, target, siteLen); }
    bool WriteCall(DWORD va, const void* target, SIZE_T siteLen) { return WriteRel32(va, 0xE8, target, siteLen); }

    bool WriteByteChecked(DWORD va, BYTE expect, BYTE value)
    {
        if (!Verify(va, &expect, 1)) { return false; }
        return WriteBytes(va, &value, 1);
    }

    void Dump(DWORD va, SIZE_T len, wchar_t* out, int cch)
    {
        static const wchar_t* kHex = L"0123456789abcdef";
        const BYTE* p = (const BYTE*)va;
        int o = 0;
        __try
        {
            for (SIZE_T i = 0; i < len && o + 4 < cch; ++i)
            {
                if (i) { out[o++] = L' '; }
                out[o++] = kHex[p[i] >> 4];
                out[o++] = kHex[p[i] & 0x0F];
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            o = 0;
            const wchar_t* err = L"<нет доступа>";
            while (*err && o + 1 < cch) { out[o++] = *err++; }
        }
        out[o] = 0;
    }
}

bool VerifyAllSites(const wchar_t* patchName, const Site* sites, int count)
{
    bool all = true;
    for (int i = 0; i < count; ++i)
    {
        if (!Hook::Verify(sites[i].va, sites[i].orig, sites[i].len))
        {
            wchar_t got[128], want[128];
            Hook::Dump(sites[i].va, sites[i].len, got, 128);
            {
                static const wchar_t* kHex = L"0123456789abcdef";
                int o = 0;
                for (SIZE_T k = 0; k < sites[i].len && o + 4 < 128; ++k)
                {
                    if (k) { want[o++] = L' '; }
                    want[o++] = kHex[sites[i].orig[k] >> 4];
                    want[o++] = kHex[sites[i].orig[k] & 0x0F];
                }
                want[o] = 0;
            }
            Log::Line(L"    MISMATCH %s @0x%08X: ожидалось [%s], в памяти [%s]",
                      patchName, sites[i].va, want, got);
            all = false;
        }
    }
    return all;
}
