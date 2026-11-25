# GameServer — операторские команды: лог SKILLPOINT + GM-гейт «неуязвимость»

> **🔄 ПЕРЕНОСИТСЯ В DLL (2026-08-04).** Правка A → `[P03_OperatorSkillPointLog]`,
> правка B → `[P04_InvincibleGmGate]` в `AsdaPatch.dll` (этап 2).
> Схема: [`dll-loader-and-patches.md`](dll-loader-and-patches.md).
> ⚠ Ссылка ниже на `RE/ida/server_work/GameServer.exe` как на «чистый эталон» УСТАРЕЛА:
> это не сток, а сток + патч расширения карт. Настоящий сток —
> `…\AsdaStory\GameServer\GameServer.exe_before_mine_patch.exe` (MD5 `4e20f0ad…`).


- **Дата:** обнаружено дифом 2026-08-04; правки внесены ранее (бинарь от 26.07.2026).
- **Статус:** ✅ ДЕЙСТВУЕТ. Автор в проекте не зафиксирован — запись создана постфактум.
- **Процесс:** GameServer.
- **Файл:** `…\v2\GameServer\GameServer.exe` (MD5 `5921a5f4ff52ba2737d7bbee057552d1`).
- **Тип:** бинарный патч — 2 перехвата + 2 code-cave.
- **Бэкап:** `GameServer.exe.bak_pre6616_20260804`; чистый эталон — `RE/ida/server_work/GameServer.exe`.

## A. Лог выдачи скиллпоинтов — `Recv_OperatorCommand_Add@0x5510F0`

**Перехват @ `0x551530`** (11 байт):
```
ориг: 8B 8D F4 FB FF FF E8 E5 D4 FD FF    mov ecx,[ebp-40Ch] ; call 0x52EA20
патч: E9 CB 14 03 00 90×6                 jmp 0x582A00
```
**Cave @ `0x582A00`:**
```
mov  ecx,[ebp-40Ch] ; mov ecx,[ecx+4] ; mov ecx,[ecx+34h]   ; CUserManager
call 0x52EA20                       ; текущее значение скиллпоинтов игрока
push eax
movzx eax, ax  ; push eax
movsx eax, word ptr [ebp+8]  ; push eax                     ; userNum
push 0x582A40                       ; "SKILLPOINT: user=%d now=%d"
push 6                              ; категория 6 = Log_Operator
call 0x569DF0
add  esp,10h
pop  eax                            ; вернуть исходный результат 0x52EA20
jmp  0x55153B
```
Строка `"SKILLPOINT: user=%d now=%d"` дописана в кейв по адресу `0x582A40`.

**Нетто-эффект:** к штатной операторской команде добавлено логирование текущего числа
скиллпоинтов в `Log_Operator\OperatorLog_*.txt`. Логика игры не меняется — исходный результат
`sub_52EA20` восстанавливается через `push eax` / `pop eax`.

## B. GM-гейт на «неуязвимость» — `Recv_OperatorCommand_Invincible@0x551870`

**Перехват @ `0x5518FF`** (10 байт):
```
ориг: 8B 55 F4 83 BA 3D BC 03 00 01   mov edx,[ebp-0Ch] ; cmp dword ptr [edx+3BC3Dh], 1
патч: E9 7C 10 03 00 90×5             jmp 0x582980
```
**Cave @ `0x582980`:**
```
movsx eax, word ptr [ebp+8] ; push eax
mov  ecx,[ebp-14h]
call 0x52ED50                       ; флаг «оператор?»
test al,al
jne  0x582996
jmp  0x551960                       ; НЕ оператор → выход из обработчика
0x582996: mov edx,[ebp-0Ch] ; cmp dword ptr [edx+3BC3Dh],1   ; исходная инструкция
jmp  0x551909
```
**Нетто-эффект:** перед включением режима неуязвимости добавлена проверка флага оператора
(`sub_52ED50`) — закрыта возможность включить его обычным игроком.

## Как ОТКАТИТЬ
`0x551530` → `8B 8D F4 FB FF FF E8 E5 D4 FD FF`; `0x5518FF` → `8B 55 F4 83 BA 3D BC 03 00 01`;
кейвы `0x582A00..0x582A32` и `0x582980..0x5829A5` и строку `0x582A40..0x582A5A` → нули.
Рестарт GameServer.

## Рестарт / риски
- **Рестарт:** GameServer.
- **Риск:** низкий. A — чисто диагностический; B — ужесточение проверки прав (откат ослабит защиту).
- **Связанное:** MEMANTO `server-operator-gate` (GM-гейт UserIndex 0..5000).
