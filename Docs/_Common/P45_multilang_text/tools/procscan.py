# Copyright (c) 2026 @sitxovski (Discord)
import re, json, sys
S = sys.argv[1]
defs = json.load(open(S + '/procdefs/defs.json', encoding='utf-8'))
BS = chr(92); defs = {n: b.replace(BS + 'r', chr(13)).replace(BS + 'n', chr(10)).replace(BS + 't', chr(9)) for n, b in defs.items()}
json.dump(defs, open(S + '/procdefs/defs_clean.json', 'w', encoding='utf-8'), ensure_ascii=False)
col = r'(?:Charname|Cname|PetName|Captain|Aname[123]|Warname|Callname|Bcharname|CharName)'
pat = re.compile(r'(?:\w+\.)?\[?' + col + r'\]?\s*=\s*@\w+|@\w+\s*=\s*(?:\w+\.)?\[?' + col + r'\]?\b', re.I)
res = {}
for n in sorted(defs):
    b = re.sub(r'--[^\n]*', '', defs[n]); b = re.sub(r'/\*.*?\*/', '', b, flags=re.S)
    for m in pat.finditer(b):
        pre = b[max(0, m.start() - 40):m.start()]
        if re.search(r'(\bset|,|\bselect|\bupdate\s+\w+\s+set)\s*$', pre, re.I):
            continue
        # строка целиком для контекста
        ls = b.rfind('\n', 0, m.start()) + 1; le = b.find('\n', m.end())
        res.setdefault(n, []).append(re.sub(r'\s+', ' ', b[ls:le if le > 0 else None]).strip()[:170])
for n in res:
    print('==', n)
    for x in dict.fromkeys(res[n]): print('    ', x)
print('procs:', len(res))
