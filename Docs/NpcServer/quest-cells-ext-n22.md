# N22_QuestCellsExt — ячейки NPC сверх 10 (AddonNPC.dll), 31.10.2026

* **Что:** запись NPC `Quest\QuestNpcTable.Bin` (1774 б) держит 10 ячеек «ВЫДАЁТ» (+34 + 86·k) и 10 «ПРИНИМАЕТ» (+894 + 88·k);
  `Start_Quest` (sub_421020, 7101) и `Process_Quest` (sub_420C10, 7103) отказывали при слоте > 9. Патч: слоты 10…127 берутся из
  `Quest\QuestNpcTableExt.Bin` (тот же формат ячеек), формат записи и протокол не меняются (слот в 5041/5043/7101/7103 — u16).
* **Где:** 0x420CB9 (`cmp word [esp+2Ah],9`, imm8 по 0x420CBE 09 → 7Fh), 0x420D3A (15 б адрес ячейки → `call TakeCellEsi`), 0x4210AD (`cmp word [esp+26h],9`, imm8 по 0x4210B2 09 → 7Fh),
  0x42112E (15 б → `call GiveCellEsi`). Байты до/после, формат таблицы — `Reports/bug_quest_follow/N22_PATCH_DESIGN.md`.
* **Зачем:** у Эллосы (56) 11 сдач (восстановленные 96, 125, 126 — bug-quest-follow); 96 — слот 10.
* **Проверки:** `AddonNPC/tools/verify_n22.py`, `stand_n22.py` (Unicorn, 140/140 слотов 0…9 = сток), run_checks.
* **Выкладка:** `AsdaPatch/tools/deploy_quest_turnin.py` (QuestNpcTable + ConditionTable + QuestNpcTableExt + AddonNPC.dll, все
  папки NpcServer по stack_layout), затем `--check-started`. Бэкап `.bak_20261031_turnin`.
* **Откат:** `[N22_QuestCellsExt] Enabled=0` (или `--rollback`; без таблицы патч не ставится — PatchLog «N22 не установлен»).
* **Рестарт:** нужен (NpcServer). **Статус:** собрано и проверено, НЕ выложено (выкладка — владелец).
