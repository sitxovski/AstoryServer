# -*- coding: utf-8 -*-
# Copyright (c) 2026 @sitxovski (Discord)
# gen_bind_vector.py — НЕЗАВИСИМАЯ (Python: cryptography + hmac) реализация привязки канала AsdaSecure
#   (контракт Reports/anticheat/eac/CONTRACT.md §8.1, EAC ред. 3, 16.10.2026) и генератор тестовых векторов.
#
#   bind = HKDF-Expand(prk, info_bind, 32);  prk = HMAC-SHA256(salt = nonceC||nonceS, ikm = общий X ECDH (big-endian, 32 б));
#   info      = u8 ver(1) · u8 subC (ClientHello[2]) · u8 subS (ServerHello[2]) · ePubC(64) · ePubS(64) · "AsdaSecure/v1\0\0\0"
#   info_bind = тот же массив, последние 16 байт = "AsdaEacBind/v1\0\0"
#   okm (ключи направлений, НЕ меняются) = HKDF-Expand(prk, info, 88): c2sKey(32) c2sIv(12) s2cKey(32) s2cIv(12).
#
#   Эфемерные ключи и nonce фиксированы (детерминированы от строки-метки) — у клиентской копии AsdaSecure вектор сверяется
#   импортом тех же закрытых скаляров. Подпись ServerHello в выводе ключей не участвует (64 нуля в векторе).
#
# Запуск: python gen_bind_vector.py <txt-вектор> <inc-для-стенда>. Без аргументов — только печать.
import hashlib
import hmac
import sys

from cryptography.hazmat.primitives.asymmetric import ec

INFO_TAIL_KEYS = b"AsdaSecure/v1\0\0\0"    # метка ключей направлений (16 б)
INFO_TAIL_BIND = b"AsdaEacBind/v1\0\0"      # метка привязки канала (16 б), контракт §8.1
assert len(INFO_TAIL_KEYS) == 16 and len(INFO_TAIL_BIND) == 16


def hkdf_expand(prk, info, n):
    """HKDF-Expand (RFC 5869) на HMAC-SHA256."""
    out, t, c = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:n]


def keypair(label):
    """Детерминированная пара P-256: d = SHA-256(метка) (заведомо < n — проверяется)."""
    d = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big")
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    assert 0 < d < n
    k = ec.derive_private_key(d, ec.SECP256R1())
    pn = k.public_key().public_numbers()
    return k, d.to_bytes(32, "big"), pn.x.to_bytes(32, "big") + pn.y.to_bytes(32, "big")


def vector(name, sub):
    """Один вектор: рукопожатие под-сервера sub с фиксированными эфемерными ключами и nonce."""
    kc, dc, pubc = keypair("AsdaEacBind/v1 test vector %s: client ephemeral" % name)
    ks, ds, pubs = keypair("AsdaEacBind/v1 test vector %s: server ephemeral" % name)
    nonce_c = hashlib.sha256(("nonceC " + name).encode()).digest()[:16]
    nonce_s = hashlib.sha256(("nonceS " + name).encode()).digest()[:16]
    ch = bytes([0xA5, 1, sub, 0]) + pubc + nonce_c
    sh = bytes([0x5A, 1, sub, 0]) + pubs + nonce_s + bytes(64)
    raw_c = kc.exchange(ec.ECDH(), ks.public_key())
    raw_s = ks.exchange(ec.ECDH(), kc.public_key())
    assert raw_c == raw_s and len(raw_c) == 32
    salt = nonce_c + nonce_s
    info = bytes([1, ch[2], sh[2]]) + pubc + pubs + INFO_TAIL_KEYS
    info_bind = info[:-16] + INFO_TAIL_BIND
    prk = hmac.new(salt, raw_c, hashlib.sha256).digest()
    okm = hkdf_expand(prk, info, 88)
    bind = hkdf_expand(prk, info_bind, 32)
    return dict(name=name, sub=sub, dc=dc, ds=ds, pubc=pubc, pubs=pubs, nonce_c=nonce_c, nonce_s=nonce_s, ch=ch, sh=sh,
                raw=raw_c, salt=salt, info=info, info_bind=info_bind, prk=prk, okm=okm, bind=bind)


def main():
    vs = [vector("game", 2), vector("indun", 3)]
    h = lambda b: b.hex()
    lines = [
        "# AsdaSecure: тестовый вектор привязки канала (EAC ред. 3, контракт CONTRACT.md §8.1), 16.10.2026",
        "# Генератор: AstoryServer/Patches/AsdaSecure/tools/gen_bind_vector.py (Python cryptography + hmac — независимо от CNG-кода).",
        "# Сверено стендом AstoryServer/Patches/AsdaSecure/stand/stand_bind.cpp: CNG-эталон == этот вектор; Session/ServerChannel/",
        "#   ClientChannel == CNG-эталон на живых рукопожатиях (у сервера и клиента одного соединения bind одинаков).",
        "#",
        "# Формулы (все байты — hex, порядок как в проводе; X ECDH — big-endian):",
        "#   ClientHello = A5 01 sub 00 | ePubC(64 = X||Y) | nonceC(16)             (84 б)",
        "#   ServerHello = 5A 01 sub 00 | ePubS(64)        | nonceS(16) | sig(64)    (148 б; sig в выводе ключей не участвует, тут нули)",
        "#   raw   = X(dC * ePubS) = X(dS * ePubC)                                   (32 б)",
        "#   salt  = nonceC || nonceS                                                (32 б)",
        "#   prk   = HMAC-SHA256(key = salt, msg = raw)",
        "#   info      = 01 | ClientHello[2] | ServerHello[2] | ePubC | ePubS | \"AsdaSecure/v1\\0\\0\\0\"   (147 б)",
        "#   info_bind = 01 | ClientHello[2] | ServerHello[2] | ePubC | ePubS | \"AsdaEacBind/v1\\0\\0\"   (147 б)",
        "#   okm   = HKDF-Expand(prk, info, 88)  = c2sKey(32) c2sIv(12) s2cKey(32) s2cIv(12)   (НЕ меняется ред. 3)",
        "#   bind  = HKDF-Expand(prk, info_bind, 32)                                 (Session::ChannelBinding)",
        "#   HKDF-Expand: T(i) = HMAC-SHA256(prk, T(i-1) | info | i), i = 1, 2, …; T(0) пусто.",
        "# Закрытые скаляры dC/dS — ТОЛЬКО для теста (детерминированы от метки), к боевому ключу сервера отношения не имеют.",
        "",
    ]
    for v in vs:
        lines += [
            "[vector %s]" % v["name"],
            "sub         = %d" % v["sub"],
            "dC          = " + h(v["dc"]),
            "ePubC       = " + h(v["pubc"]),
            "dS          = " + h(v["ds"]),
            "ePubS       = " + h(v["pubs"]),
            "nonceC      = " + h(v["nonce_c"]),
            "nonceS      = " + h(v["nonce_s"]),
            "ClientHello = " + h(v["ch"]),
            "ServerHello = " + h(v["sh"]),
            "raw         = " + h(v["raw"]),
            "salt        = " + h(v["salt"]),
            "info        = " + h(v["info"]),
            "info_bind   = " + h(v["info_bind"]),
            "prk         = " + h(v["prk"]),
            "c2sKey      = " + h(v["okm"][0:32]),
            "c2sIv       = " + h(v["okm"][32:44]),
            "s2cKey      = " + h(v["okm"][44:76]),
            "s2cIv       = " + h(v["okm"][76:88]),
            "bind        = " + h(v["bind"]),
            "",
        ]
    txt = "\n".join(lines)
    print(txt)
    if len(sys.argv) >= 3:
        with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
            f.write(txt)
        c = lambda b: ", ".join("0x%02X" % x for x in b)
        inc = ["// bind_test_vector.inc — СГЕНЕРИРОВАН tools/gen_bind_vector.py (не править руками). EAC ред. 3, CONTRACT.md §8.1.",
               "// Поля: sub, dC, ePubC, dS, ePubS, nonceC, nonceS, okm(88), bind(32)."]
        for v in vs:
            inc.append("{ %d, {%s}, {%s}, {%s}, {%s}, {%s}, {%s}, {%s}, {%s} }," % (
                v["sub"], c(v["dc"]), c(v["pubc"]), c(v["ds"]), c(v["pubs"]), c(v["nonce_c"]), c(v["nonce_s"]),
                c(v["okm"]), c(v["bind"])))
        with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(inc) + "\n")


if __name__ == "__main__":
    main()
