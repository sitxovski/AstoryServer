// Copyright (c) 2026 @sitxovski (Discord)
const fs = require("fs");
const crypto = require("crypto");
const net = require("net");
const path = require("path");
const { execFileSync } = require("child_process");

const root = __dirname;
const configPath = path.join(root, "config.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8").replace(/^\uFEFF/, ""));
const logsDir = path.join(root, "logs");
const balancesPath = path.resolve(root, config.balancesFile || "balances.json");

fs.mkdirSync(logsDir, { recursive: true });

function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

function dayName() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
}

function hexDump(buffer, maxBytes) {
  const slice = buffer.subarray(0, maxBytes);
  const rows = [];
  for (let offset = 0; offset < slice.length; offset += 16) {
    const part = slice.subarray(offset, offset + 16);
    const hex = [...part].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
    const ascii = [...part].map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    rows.push(`${offset.toString(16).padStart(4, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return rows.join("\n");
}

function toHex(buffer) {
  return [...buffer].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join("");
}

function writeLog(line) {
  const file = path.join(logsDir, `gp7-${dayName()}.log`);
  fs.appendFileSync(file, `${stamp()} ${line}\n`, "utf8");
}

let luckyBoxPools;
let premiumItemMap;
let functionItemPrices;

// ★ 25.10.2026 (ревизия wave_1025: «кэш цен item_table живёт до перезапуска шлюза»): таблицы и карта коробок перечитываются,
//   когда у файла меняются время записи или размер. Отпечаток «нет файла» — тоже значение (появится — перечитаем).
const fileStamps = new Map();
function fileChanged(key, filePath) {
  let stamp = "missing";
  try {
    const st = fs.statSync(filePath);
    stamp = `${st.mtimeMs}:${st.size}`;
  } catch (err) {
    stamp = "missing";
  }
  if (fileStamps.get(key) === stamp) {
    return false;
  }
  fileStamps.set(key, stamp);
  return true;
}

function loadPremiumItemMap() {
  const mapPath = path.resolve(root, config.premiumItemMap || "premium_item_map.json");
  if (premiumItemMap && !fileChanged("premiumItemMap", mapPath)) {
    return premiumItemMap;
  }
  fileChanged("premiumItemMap", mapPath);
  const source = fs.existsSync(mapPath)
    ? JSON.parse(fs.readFileSync(mapPath, "utf8").replace(/^\uFEFF/, ""))
    : {};
  premiumItemMap = new Map();

  for (const [catalogCode, mappingValue] of Object.entries(source)) {
    const catalog = Number(catalogCode);
    const mapping = typeof mappingValue === "object" && mappingValue !== null
      ? mappingValue
      : { deliveryItemCode: mappingValue };
    const deliveryItemCode = Number(mapping.deliveryItemCode);
    const price = Number(mapping.price);
    if (!Number.isInteger(catalog) || catalog <= 0 ||
        !Number.isInteger(deliveryItemCode) || deliveryItemCode <= 0 ||
        !Number.isInteger(price) || price < 0) {
      throw new Error(`Invalid premium item mapping: ${catalogCode} -> ${JSON.stringify(mappingValue)}`);
    }
    premiumItemMap.set(catalog, { deliveryItemCode, price });
  }

  writeLog(`PREMIUM_ITEM_MAP_OK file=${JSON.stringify(mapPath)} rows=${premiumItemMap.size}`);
  return premiumItemMap;
}

// ★ 18.10.2026: позиции витрины с кодом <= 558 без строки в premium_item_map.json (карта сайта покрывает 50 из 261)
//   раньше отклонялись (missing-premium-item-map). Если код — функциональный предмет сервера (GameServer
//   ItemTable_Info/Function_Table.txt, цена — 21-я колонка), выдаём его под своим кодом по цене таблицы.
function loadFunctionItemPrices() {
  const tablePath = path.resolve(root, config.functionTable || "../GameServer/ItemTable_Info/Function_Table.txt");
  if (functionItemPrices && !fileChanged("functionTable", tablePath)) {
    return functionItemPrices;
  }
  fileChanged("functionTable", tablePath);
  functionItemPrices = new Map();
  try {
    const lines = fs.readFileSync(tablePath, "latin1").split(/\r?\n/);
    for (const line of lines) {
      const t = line.trim().split(/\s+/);
      if (t.length > 20 && /^\d+$/.test(t[0]) && /^\d+$/.test(t[20])) {
        functionItemPrices.set(Number(t[0]), Number(t[20]));
      }
    }
    writeLog(`FUNCTION_TABLE_OK file=${JSON.stringify(tablePath)} rows=${functionItemPrices.size}`);
  } catch (err) {
    writeLog(`FUNCTION_TABLE_ERROR ${err.message}`);
  }
  return functionItemPrices;
}

// ★ 23.10.2026: граница «функциональный предмет» = код есть в Function_Table.txt (а не жёсткое <= 558):
//   в таблицу добавлены коды 559…637 (маунты донора AsdaFableClassic, Reports/fable_mounts/FABLE_MOUNTS.md).
//   Для кодов <= 558 поведение прежнее, в том числе если таблица не прочиталась.
function isFunctionItem(itemCode) {
  return itemCode <= 558 || loadFunctionItemPrices().has(itemCode);
}

// ★ 24.10.2026 (Reports/fable_mounts, баг «купил маунт — ничего, дальше "Сервер не отвечает"»): GameServer принимает
//   ответ подтипа 1 ТОЛЬКО с кодом обычного предмета: sub_4F6650 @0x4F69DC → sub_532A90(code) =
//   code >= 20551 && code <= count(item_table.txt) + 20550. Иначе он пишет «GP7's Response ItemCode is Invalid» и
//   НИЧЕГО не отвечает клиенту (защёлка магазина висит), а счёт уже списан. Функциональные предметы оригинал продаёт
//   КОРОБКОЙ (item_table 11/200 → PackageItem_Table) через premium_item_map.json. Если выдать нечем (код вне
//   диапазона) — НЕ списываем и отвечаем status 0: GameServer шлёт клиенту штатный отказ 5071 (ветка «GP7's Response
//   is failure»). Ключ config.rejectUndeliverable (по умолчанию включён; false = как раньше).
let itemTableMaxCode;
function loadItemTableMaxCode() {
  const tablePath = path.resolve(root, config.itemTable || "../GameServer/ItemTable_Info/item_table.txt");
  if (itemTableMaxCode !== undefined && !fileChanged("itemTableHead", tablePath)) {
    return itemTableMaxCode;
  }
  fileChanged("itemTableHead", tablePath);
  itemTableMaxCode = 0;
  try {
    const fd = fs.openSync(tablePath, "r");
    const head = Buffer.alloc(32);
    fs.readSync(fd, head, 0, head.length, 0);
    fs.closeSync(fd);
    const count = Number((head.toString("latin1").match(/^\s*(\d+)/) || [])[1]);
    if (Number.isInteger(count) && count > 0) {
      itemTableMaxCode = count + 20550;
    }
    writeLog(`ITEM_TABLE_OK file=${JSON.stringify(tablePath)} count=${count} maxCode=${itemTableMaxCode}`);
  } catch (err) {
    writeLog(`ITEM_TABLE_ERROR ${err.message}`);
  }
  return itemTableMaxCode;
}

// ★ 25.10.2026 (баг игроков «купил в премиум-магазине 3 штуки — пришла 1»; 19.10 Player17 75702 ×3, заказ 10908):
//   стоковый GameServer собирает корзину 5070 (до 7 позиций) в CharChargeShopBuy@0x511DA0, суммирует их цены в BuyCash,
//   но в запрос шлюзу (sub_4F60E0, ветка 137 «Premium Item Buy Request») кладёт ТОЛЬКО код позиции 0 (v50[23]) и ВСЮ
//   сумму (v50[17]). Ответ подтипа 1 несёт один код → SendNewPremiumPacket выдаёт ОДНУ вещь (Count 1) в ItemPostBox.
//   Раньше шлюз списывал присланную сумму целиком (для кодов item_table цена не сверялась): корзина из трёх по 10 000
//   → GP7PurchaseLog 30 000, а в почте один предмет. Теперь для кода item_table сверяем присланную цену с ценой ОДНОЙ
//   штуки (колонка 26 item_table.txt = поле записи +41, ровно её GameServer кладёт в BuyCash) и при расхождении НЕ
//   списываем и отвечаем status 0 — GameServer шлёт клиенту штатный отказ 5071 (ветка «GP7's Response is failure»).
//   ★ С AsdaPatch P85 (25.10.2026) GameServer присылает и все коды корзины — тогда работает путь «корзина целиком»
//   (readCartExtension / resolveCart ниже), а эта проверка остаётся только для запроса БЕЗ расширения (P85 выключен):
//   сумма корзины за один код по-прежнему отклоняется без списания. Ключ config.rejectCartTotal (false = как раньше).
let itemTablePrices;
function loadItemTablePrices() {
  const tablePath = path.resolve(root, config.itemTable || "../GameServer/ItemTable_Info/item_table.txt");
  if (itemTablePrices && !fileChanged("itemTablePrices", tablePath)) {
    return itemTablePrices;
  }
  fileChanged("itemTablePrices", tablePath);
  itemTablePrices = new Map();
  try {
    const lines = fs.readFileSync(tablePath, "latin1").split(/\r?\n/);
    for (let i = 1; i < lines.length; ++i) {
      const t = lines[i].trim().split(/\s+/);
      if (t.length > 26 && /^\d+$/.test(t[0]) && /^-?\d+$/.test(t[26])) {
        itemTablePrices.set(Number(t[0]), Number(t[26]));
      }
    }
    writeLog(`ITEM_PRICE_TABLE_OK file=${JSON.stringify(tablePath)} rows=${itemTablePrices.size}`);
  } catch (err) {
    writeLog(`ITEM_PRICE_TABLE_ERROR ${err.message}`);
  }
  return itemTablePrices;
}

// true = присланная цена — сумма корзины, а не цена одной штуки кода (выдать за неё GameServer может только одну).
//   Цены у кода нет (таблица не прочиталась) — не мешаем, как isDeliverableItemCode.
function isCartTotalPrice(itemCode, price) {
  if (config.rejectCartTotal === false) {
    return false;
  }
  const unit = loadItemTablePrices().get(itemCode);
  return unit !== undefined && price !== unit;
}

// Код, который GameServer сможет выдать по ответу подтипа 1 (повтор sub_532A90). Таблица не прочиталась — не мешаем.
function isDeliverableItemCode(itemCode) {
  if (config.rejectUndeliverable === false) {
    return true;
  }
  const maxCode = loadItemTableMaxCode();
  return itemCode >= 20551 && (maxCode === 0 || itemCode <= maxCode);
}

// ★★★ 25.10.2026 [ИСПРАВЛЕНИЕ] КОРЗИНА ЦЕЛИКОМ (слово владельца: «корзина из нескольких позиций должна проходить»).
//   GameServer с AsdaPatch P85 дописывает в хвост запроса 0x50 (поле channel @112) расширение корзины:
//     @128 'CRT7', @132 7×int32 коды позиций (0 = пустая/негодная — сток её не посчитал), @160 число позиций.
//   Шлюз разрешает КАЖДУЮ позицию той же логикой, что одиночную покупку (карта коробок / Function_Table / item_table),
//   сверяет присланную сумму (BuyCash GameServer = сумма цен позиций) с суммой цен, списывает ОДИН раз и в той же
//   транзакции пишет позиции в Joy1.dbo.ItemPostBoxCart (purchaseSqlAccount). В ответе — код позиции 0, как в стоке;
//   UPCashitemBuy раскладывает корзину строками одного заказа ящика. Любая непригодная позиция — отказ всей корзины
//   без списания (status 0 → штатный 5071 код 0). Без расширения (GameServer без P85) — прежний путь, где сумма
//   корзины за один код отклоняется (rejectCartTotal).
// ★ r2 (25.10.2026, баг владельца «купил 7 — в строке 6»): метка 'CRT8' — коды САМОГО пакета 5070 (смешанная корзина
//   item_list + special_itemlist одним пакетом), @161 — байт «таблица» пакета, @162 — сколько позиций принял GameServer (их
//   цены — BuyCash). Позиции другой таблицы CharChargeShopBuy молча пропускает — шлюз их тоже разрешает, сверяет BuyCash с
//   суммой ПРИНЯТЫХ сервером и списывает за все. 'CRT7' (r1) — коды записей корзины, как раньше.
function readCartExtension(payload) {
  const tag = payload.length >= 161 ? payload.toString("latin1", 128, 132) : "";
  if (config.acceptCart === false || (tag !== "CRT7" && tag !== "CRT8")) {
    return null;
  }
  const codes = [];
  for (let i = 0; i < 7; ++i) {
    const code = payload.readInt32LE(132 + 4 * i);
    if (code > 0) {
      codes.push(code);
    }
  }
  return tag === "CRT8"
    ? { codes, declared: payload[160], version: 8, table: payload[161], accepted: payload[162] }
    : { codes, declared: payload[160], version: 7 };
}

// Код из item_list (ветка «таблица 1» CharChargeShopBuy, sub_532A90), иначе — спец-таблица (sub_532B10).
function isItemListCode(itemCode) {
  return itemCode >= 20551 && loadItemTablePrices().has(itemCode);
}

// Позиция подтипа 1 → { delivery, unit } или { error } (повтор одиночного пути buildPurchaseResponse).
// ★ 01.11.2026 P101_CashGift: opts.ignoreDelivery = true — подарок (buildGiftResponse). Получатель получает в сумку сам
//   каталожный код (sub_4D6740), а не коробку из ящика, поэтому проверка undeliverable-item-code не нужна. Цена та же — цена витрины.
function resolvePremiumItem(itemCode, opts) {
  const mappings = loadPremiumItemMap();
  const functionPrice = isFunctionItem(itemCode) && !mappings.get(itemCode)
    ? loadFunctionItemPrices().get(itemCode)
    : undefined;
  const mapping = mappings.get(itemCode) ||
    (functionPrice !== undefined ? { deliveryItemCode: itemCode, price: functionPrice } : null);
  if (isFunctionItem(itemCode) && !mapping) {
    return { error: "missing-premium-item-map" };
  }
  const delivery = mapping ? mapping.deliveryItemCode : itemCode;
  if (!(opts && opts.ignoreDelivery) && !isDeliverableItemCode(delivery)) {
    return { error: "undeliverable-item-code" };
  }
  const unit = mapping ? mapping.price : loadItemTablePrices().get(itemCode);
  if (unit === undefined) {
    return { error: "unknown-item-price" };
  }
  return { delivery, unit };
}

// Корзина → { rows: [{ slot, code, price }], sum } или { error, code }. ext.version 8: price (BuyCash) сверяется с суммой
//   позиций той таблицы, что принял сервер (ext.table), их число — с ext.accepted; списывается сумма ВСЕХ позиций.
function resolveCart(ext, price) {
  const codes = ext.codes;
  const rows = [];
  let sum = 0;
  let serverSum = 0;
  let serverCount = 0;
  for (let i = 0; i < codes.length; ++i) {
    const r = resolvePremiumItem(codes[i]);
    if (r.error) {
      return { error: `cart-${r.error}`, code: codes[i], sum };
    }
    rows.push({ slot: i, code: r.delivery, price: r.unit });
    sum += r.unit;
    if (ext.version === 8 && (ext.table ? isItemListCode(codes[i]) : !isItemListCode(codes[i]))) {
      serverSum += r.unit;
      ++serverCount;
    }
  }
  if (ext.version === 8) {
    if (serverCount !== ext.accepted) {
      return { error: "cart-accept-mismatch", sum, code: serverCount };
    }
    if (serverSum !== price) {
      return { error: "cart-price-mismatch", sum: serverSum };
    }
    return { rows, sum };
  }
  if (sum !== price) {
    return { error: "cart-price-mismatch", sum };
  }
  return { rows, sum };
}

// ★ 18.10.2026: учётки игроков есть в игровой базе (AsdaStoryOP.dbo.Us_member), но не в таблице сайта dbo.[user],
//   к которой привязаны баланс и журнал GP7 — магазин им всегда отказывал (found=false / status 0). Если такой
//   игровой учётки нет на сайте, заводим строку (роль GA, случайный пароль — входом на сайт не служит).
//   Ключ config.autoProvisionGameAccounts (по умолчанию включён).
function siteUserProvisionSql(account) {
  if (config.autoProvisionGameAccounts === false) {
    return "";
  }
  const a = sqlString(account);
  return `IF NOT EXISTS (SELECT 1 FROM dbo.[user] WHERE username='${a}') ` +
    `AND EXISTS (SELECT 1 FROM AsdaStoryOP.dbo.Us_member WHERE us_id='${a}') ` +
    `INSERT dbo.[user] (username, password, name, role) VALUES ('${a}', CONVERT(VARCHAR(50), NEWID()), NULL, 'GA'); `;
}

function loadLuckyBoxPools() {
  if (luckyBoxPools) {
    return luckyBoxPools;
  }

  const tablePath = path.resolve(
    root,
    config.luckyBoxTable || "../GameServer/ItemTable_Info/PrimiumGaChaTable.txt"
  );
  const lines = fs.readFileSync(tablePath, "utf8")
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const declaredCount = Number(lines.shift());
  const pools = new Map();

  for (const line of lines) {
    const fields = line.split(/\s+/).map(Number);
    if (fields.length < 4 || fields.some((value) => !Number.isInteger(value))) {
      throw new Error(`Invalid LuckyBox table row: ${JSON.stringify(line)}`);
    }

    const [index, boxType, itemCode, count] = fields;
    if (itemCode <= 0 || count <= 0) {
      continue;
    }
    if (!pools.has(boxType)) {
      pools.set(boxType, []);
    }
    pools.get(boxType).push({ index, itemCode, count });
  }

  const parsedCount = [...pools.values()].reduce((sum, rows) => sum + rows.length, 0);
  if (!Number.isInteger(declaredCount) || parsedCount !== declaredCount) {
    throw new Error(`LuckyBox row count mismatch: declared=${declaredCount} parsed=${parsedCount}`);
  }

  luckyBoxPools = pools;
  writeLog(`LUCKYBOX_TABLE_OK file=${JSON.stringify(tablePath)} rows=${parsedCount} types=${pools.size}`);
  return luckyBoxPools;
}

// ★ 22.11.2026 [ИСПРАВЛЕНИЕ] (Reports/admin_center/research_gp7_orphan_orders_20261121.md, «лаки-бокс»): код награды
//   проверяется ДО списания. Проверка подтипа 1 (isDeliverableItemCode, код >= 20551) сюда НЕ годится: ветка ответа
//   subtype 2 GameServer (GameServer.c:95236-95262) sub_532A90 не вызывает, а у box type 0 живой PrimiumGaChaTable
//   есть функциональные награды < 20551 (30, 196, 197, 334, 476 …) — 257 из 259 таких заказов выданы (CashUse есть).
//   Поэтому награда годна, если это предмет item_table (код <= конца item_table) или функциональный предмет в том же смысле,
//   что у витрины (isFunctionItem: код <= 558 или есть в Function_Table); иначе — отказ status 0 без списания
//   (source unknown-reward-code). Таблица не прочиталась — не мешаем (как isDeliverableItemCode / isFunctionItem).
//   Ключ config.rejectUnknownRewardCode (false = как раньше: награда без проверки).
function isKnownRewardCode(itemCode) {
  if (config.rejectUnknownRewardCode === false) {
    return true;
  }
  if (itemCode >= 20551) {
    // ★ ревизия 53 М-1: не через isDeliverableItemCode — та уважает rejectUndeliverable (ключ подтипа 1), и его выключение
    //   молча снимало бы половину проверки награды. Здесь граница item_table та же, а управляет только rejectUnknownRewardCode.
    const maxCode = loadItemTableMaxCode();
    return maxCode === 0 || itemCode <= maxCode;
  }
  return isFunctionItem(itemCode) || loadFunctionItemPrices().size === 0;
}

function selectLuckyBoxReward(boxType) {
  const rows = loadLuckyBoxPools().get(boxType);
  if (!rows || rows.length === 0) {
    return null;
  }
  return rows[crypto.randomInt(rows.length)];
}
function readFrame(buffer) {
  if (buffer.length < 10 || buffer[0] !== 0xfb) {
    return null;
  }

  const declaredLength = buffer.readUInt16LE(1);
  if (declaredLength !== buffer.length || buffer[buffer.length - 1] !== 0xfe) {
    return null;
  }

  return {
    kind: buffer.readUInt16LE(3),
    route: buffer.readUInt16LE(5),
    command: buffer.readUInt16LE(7),
    payload: buffer.subarray(9, buffer.length - 1),
  };
}

function readAccount(payload) {
  const field = payload.subarray(0, 61);
  const terminator = field.indexOf(0);
  return field.subarray(0, terminator < 0 ? field.length : terminator).toString("utf8").trim();
}

function readFixedText(payload, offset, length) {
  const field = payload.subarray(offset, offset + length);
  const terminator = field.indexOf(0);
  return field.subarray(0, terminator < 0 ? field.length : terminator).toString("utf8").trim();
}

function accountKey(account) {
  return account.toLowerCase();
}

function defaultBalance() {
  return {
    balance: Number(config.defaultPremiumBalance || 0) >>> 0,
    present: Number(config.defaultPremiumPresent || 0) >>> 0,
    found: false,
  };
}

function readJsonAccountBalance(account) {
  const fallback = {
    ...defaultBalance(),
    source: "default",
  };

  if (!account || !fs.existsSync(balancesPath)) {
    return fallback;
  }

  try {
    const balances = JSON.parse(fs.readFileSync(balancesPath, "utf8").replace(/^\uFEFF/, ""));
    const entry = balances[accountKey(account)];
    if (entry === undefined) {
      return fallback;
    }

    if (typeof entry === "number") {
      return { balance: Number(entry) >>> 0, present: 0, found: true, source: "json" };
    }

    return {
      balance: Number(entry.balance || 0) >>> 0,
      present: Number(entry.present || 0) >>> 0,
      found: true,
      source: "json",
    };
  } catch (err) {
    writeLog(`BALANCE_FILE_ERROR ${err.message}`);
    return fallback;
  }
}

function sqlString(value) {
  return value.replace(/'/g, "''");
}

function readSqlAccountBalance(account) {
  const fallback = { ...defaultBalance(), source: "sql-fallback" };
  const sql = config.sql || {};

  if (!account || Buffer.byteLength(account, "utf8") > 50) {
    return fallback;
  }

  try {
    const query =
      `SET NOCOUNT ON; ${siteUserProvisionSql(account)}EXEC dbo.GP7_GetBalance @username='${sqlString(account)}';`;
    const output = execFileSync(sql.command || "SQLCMD.EXE", [
      "-S", sql.server || "@@ASTORY_SERVER_LAN_IP@@",
      "-E",
      "-C",
      "-d", sql.database || "AsdaStoryLogin",
      "-b",
      "-h", "-1",
      "-W",
      "-s", "|",
      "-Q", query,
    ], {
      encoding: "utf8",
      timeout: Number(sql.timeoutMs || 5000),
      windowsHide: true,
    });

    const row = output.split(/\r?\n/).map((line) => line.trim()).find((line) => /^\d+\|\d+\|[01]$/.test(line));
    if (!row) {
      throw new Error(`Unexpected sqlcmd response: ${JSON.stringify(output.trim())}`);
    }

    const [balance, present, found] = row.split("|").map(Number);
    return {
      balance: balance >>> 0,
      present: present >>> 0,
      found: found === 1,
      source: "sql",
    };
  } catch (err) {
    writeLog(`SQL_BALANCE_ERROR account=${JSON.stringify(account)} ${err.message}`);
    return fallback;
  }
}

// ТЕСТОВЫЙ РЕЖИМ (18.10.2026, владелец: «любому игроку баланс 999999, пусть кайфуют на тесте»).
//   config.testFixedBalance > 0 — магазин показывает ЛЮБОМУ игроку этот баланс, а покупка проходит без
//   списания: перед GP7_Purchase счёт пополняется на сумму покупки (см. purchaseSqlAccount), так что
//   журнал GP7PurchaseLog и номер заказа настоящие, а баланс в базе не меняется. 0 / нет ключа — как раньше.
function testFixedBalance() {
  return Number(config.testFixedBalance || 0) >>> 0;
}

function readAccountBalance(account) {
  const real = String(config.balanceSource || "json").toLowerCase() === "sql"
    ? readSqlAccountBalance(account)
    : readJsonAccountBalance(account);
  const fixed = testFixedBalance();
  return fixed > 0 && account ? { ...real, balance: fixed, found: true, source: `${real.source}+test-fixed` } : real;
}

function installSqlSchema() {
  if (String(config.balanceSource || "json").toLowerCase() !== "sql") {
    return;
  }

  const sql = config.sql || {};
  const migration = path.join(root, "install_gp7_balance.sql");
  try {
    execFileSync(sql.command || "SQLCMD.EXE", [
      "-S", sql.server || "@@ASTORY_SERVER_LAN_IP@@",
      "-E",
      "-C",
      "-d", sql.database || "AsdaStoryLogin",
      "-b",
      // ★ 02.11.2026 P101 (ревизия М7): установщик — UTF-8 (русские комментарии к объявлениям P101). Без -f sqlcmd читает файл
      //   в OEM-кодировке, и в sys.sql_modules комментарии ложатся кракозябрами. Вне комментариев не-ASCII нет, ASCII-часть
      //   прежнего установщика читается одинаково.
      "-f", "65001",
      "-i", migration,
    ], {
      encoding: "utf8",
      timeout: Number(sql.migrationTimeoutMs || 15000),
      windowsHide: true,
    });
    writeLog(`SQL_MIGRATION_OK file=${JSON.stringify(migration)}`);
  } catch (err) {
    writeLog(`SQL_MIGRATION_ERROR ${err.message}`);
    throw err;
  }
}

// cartRows (25.10.2026, корзина целиком): [{ slot, code, price }] — позиции корзины, которые в ТОЙ ЖЕ транзакции, что и
//   списание, ложатся в Joy1.dbo.ItemPostBoxCart под номером заказа (= id строки GP7PurchaseLog, как orderIndex ответа).
//   Любая ошибка вставки откатывает и списание (SET XACT_ABORT ON) — sqlcmd -b падает, ответ status 0, денег не берём.
function purchaseSqlAccount(account, itemCode, amount, cartRows) {
  const fallback = { status: 0, balance: 0, present: 0, purchaseId: 0, source: "sql-error" };
  const sql = config.sql || {};

  if (!account || Buffer.byteLength(account, "utf8") > 50 || amount <= 0) {
    return { ...fallback, source: "invalid-request" };
  }

  try {
    // Вторым набором строк забираем id только что записанной строки
    // dbo.GP7PurchaseLog — он идёт в номер заказа (см. buildPurchaseResponse).
    // @@IDENTITY привязан к сессии sqlcmd, а последняя инструкция процедуры —
    // SELECT, поэтому к этому моменту в ней лежит id журнала покупок.
    // Через INSERT ... EXEC во временную таблицу так сделать НЕЛЬЗЯ: вставка
    // в таблицу без identity-колонки обнуляет @@IDENTITY (проверено).
    // Тестовый режим: пополнить счёт на сумму покупки ДО списания (итог в базе — без изменений).
    // ★ 22.11.2026 (ревизия 63 М-5 / Н-3, ТОЛЬКО тестовый режим, решение владельца «Да, чинить»): учётка сайта берётся под UPDLOCK,
    //   HOLDLOCK — порядок замков тот же, что у dbo.GP7_Purchase и adm.GP7Adjust панели ([user] → GP7Balance), и пополнение с покупкой
    //   идут ОДНОЙ транзакцией (корзина — как и была, одиночная покупка — ниже): корректировка баланса панелью не видит «реальный + цена»
    //   между ними и не встаёт в цикл замков. При testFixedBalance = 0 topUp пуст — боевые ветки и их текст SQL побайтно прежние.
    const topUp = testFixedBalance() > 0
      ? `DECLARE @tu BIGINT; SELECT TOP (1) @tu = id FROM dbo.[user] WITH (UPDLOCK, HOLDLOCK) WHERE username='${sqlString(account)}'; ` +
        `IF @tu IS NOT NULL BEGIN ` +
        `IF NOT EXISTS (SELECT 1 FROM dbo.GP7Balance WHERE user_id=@tu) INSERT dbo.GP7Balance (user_id, balance, present) VALUES (@tu, 0, 0); ` +
        `UPDATE dbo.GP7Balance SET balance = balance + ${Number(amount)} WHERE user_id=@tu; END; `
      : "";
    const cart = Array.isArray(cartRows) && cartRows.length > 1 ? cartRows : null;
    const cartValues = cart
      ? cart.map((r) => `(((@pid - 1) % 2147483647) + 1, ${Number(r.slot)}, ${Number(r.code)}, ${Number(r.price)})`).join(", ")
      : "";
    const query = cart
      ? `SET NOCOUNT ON; SET XACT_ABORT ON; BEGIN TRAN; ${siteUserProvisionSql(account)}${topUp}EXEC dbo.GP7_Purchase ` +
        `@username='${sqlString(account)}', @item_code=${itemCode}, @amount=${amount}; ` +
        `DECLARE @pid BIGINT; SET @pid = CAST(ISNULL(@@IDENTITY, 0) AS BIGINT); ` +
        `IF EXISTS (SELECT 1 FROM dbo.GP7PurchaseLog WHERE id = @pid AND success = 1 AND item_code = ${itemCode} ` +
        `AND amount = ${amount} AND created_at >= DATEADD(second, -60, SYSUTCDATETIME())) ` +
        `INSERT Joy1.dbo.ItemPostBoxCart (Orderidx, Slot, Code, Price) VALUES ${cartValues}; ` +
        `COMMIT TRAN; SELECT @pid;`
      : topUp
      ? `SET NOCOUNT ON; SET XACT_ABORT ON; BEGIN TRAN; ${siteUserProvisionSql(account)}${topUp}EXEC dbo.GP7_Purchase ` +
        `@username='${sqlString(account)}', @item_code=${itemCode}, @amount=${amount}; ` +
        `DECLARE @pid BIGINT; SET @pid = CAST(ISNULL(@@IDENTITY, 0) AS BIGINT); COMMIT TRAN; SELECT @pid;`
      : `SET NOCOUNT ON; ${siteUserProvisionSql(account)}${topUp}EXEC dbo.GP7_Purchase ` +
        `@username='${sqlString(account)}', @item_code=${itemCode}, @amount=${amount}; ` +
        `SELECT CAST(ISNULL(@@IDENTITY, 0) AS BIGINT);`;
    const output = execFileSync(sql.command || "SQLCMD.EXE", [
      "-S", sql.server || "@@ASTORY_SERVER_LAN_IP@@",
      "-E",
      "-C",
      "-d", sql.database || "AsdaStoryLogin",
      "-b",
      "-h", "-1",
      "-W",
      "-s", "|",
      "-Q", query,
    ], {
      encoding: "utf8",
      timeout: Number(sql.timeoutMs || 5000),
      windowsHide: true,
    });

    const lines = output.split(/\r?\n/).map((line) => line.trim());
    const rowIndex = lines.findIndex((line) => /^[012]\|\d+\|\d+$/.test(line));
    if (rowIndex < 0) {
      throw new Error(`Unexpected sqlcmd response: ${JSON.stringify(output.trim())}`);
    }
    const row = lines[rowIndex];
    // id идёт следующим набором строк, отдельной строкой из одних цифр
    const idLine = lines.slice(rowIndex + 1).find((line) => /^\d+$/.test(line));

    const [status, balance, present] = row.split("|").map(Number);
    return {
      status,
      balance: balance >>> 0,
      present: present >>> 0,
      purchaseId: idLine ? Number(idLine) : 0,
      source: "sql",
    };
  } catch (err) {
    writeLog(`SQL_PURCHASE_ERROR account=${JSON.stringify(account)} itemCode=${itemCode} amount=${amount} ${err.message}`);
    return fallback;
  }
}

function buildBalanceResponse(request) {
  const frame = readFrame(request);
  if (!frame || frame.command !== 0x5a || frame.payload.length < 67) {
    return null;
  }

  // GetBalance request payload:
  // account[61], userIndex (DWORD), userNum (WORD).
  const account = readAccount(frame.payload);
  const userIndex = frame.payload.readUInt32LE(61);
  const userNum = frame.payload.readUInt16LE(65);
  const accountBalance = readAccountBalance(account);

  // GameServer::Recv_GP7Response(type=1) copies exactly 15 bytes:
  // status, userIndex, userNum, balance, present.
  const payload = Buffer.alloc(15, 0);
  payload[0] = 1;
  payload.writeUInt32LE(userIndex, 1);
  payload.writeUInt16LE(userNum, 5);
  payload.writeUInt32LE(accountBalance.balance, 7);
  payload.writeUInt32LE(accountBalance.present, 11);

  const response = Buffer.alloc(9 + payload.length + 1, 0);
  response[0] = 0xfb;
  response.writeUInt16LE(response.length, 1);
  response.writeUInt16LE(frame.kind, 3);
  response.writeUInt16LE(frame.route, 5);
  response.writeUInt16LE(0x5b, 7);
  payload.copy(response, 9);
  response[response.length - 1] = 0xfe;

  return { response, account, userIndex, userNum, ...accountBalance };
}

function buildPurchaseResponse(request) {
  const frame = readFrame(request);
  if (!frame || frame.command !== 0x50 || frame.payload.length < 173) {
    return null;
  }

  // Buy request payload assembled by GameServer::SendToArabPremiumAgent:
  // subtype, userIndex, account[61], itemCode, flag, count, character[20],
  // item metadata, userNum/flags, price, reserved, channel[61].
  const subtype = frame.payload[0];
  const userIndex = frame.payload.readUInt32LE(1);
  const account = readFixedText(frame.payload, 5, 61);
  const itemCode = frame.payload.readUInt32LE(66);
  const requestFlag = frame.payload[103];
  const price = frame.payload.readUInt32LE(104);
  const userNum = frame.payload.readUInt32LE(99) & 0xffff;
  const boxType = subtype === 2 ? frame.payload[71] : null;
  const reward = subtype === 2 ? selectLuckyBoxReward(boxType) : null;
  const unknownReward = subtype === 2 && reward !== null && !isKnownRewardCode(reward.itemCode);   // ★ 22.11.2026: см. isKnownRewardCode
  // ★ 25.10.2026 корзина целиком (P85): ≥ 2 позиций — свой путь (resolveCart), иначе прежний одиночный.
  const cartExt = subtype === 1 ? readCartExtension(frame.payload) : null;
  const cart = cartExt && cartExt.codes.length > 1 ? resolveCart(cartExt, price) : null;
  const premiumMappings = subtype === 1 ? loadPremiumItemMap() : null;
  const functionPrice = subtype === 1 && isFunctionItem(itemCode) && !premiumMappings.get(itemCode)
    ? loadFunctionItemPrices().get(itemCode)
    : undefined;
  const premiumMapping = subtype === 1
    ? (premiumMappings.get(itemCode) ||
       (functionPrice !== undefined ? { deliveryItemCode: itemCode, price: functionPrice } : null))
    : null;
  const missingPremiumMapping = subtype === 1 && isFunctionItem(itemCode) && !premiumMapping;
  const invalidPremiumPrice = Boolean(premiumMapping && price !== premiumMapping.price);
  const authoritativePrice = premiumMapping ? premiumMapping.price : price;
  const mappedItemCode = subtype === 1
    ? (premiumMapping ? premiumMapping.deliveryItemCode : itemCode)
    : itemCode;
  const rewardItemCode = subtype === 2 ? (reward ? reward.itemCode : 0) : mappedItemCode;
  const rewardCount = subtype === 2 ? (reward ? reward.count : 0) : 1;
  const billingItemCode = subtype === 2 ? rewardItemCode : itemCode;
  const undeliverable = subtype === 1 && !missingPremiumMapping && !isDeliverableItemCode(mappedItemCode);
  // ★ 25.10.2026: корзина из нескольких позиций — GameServer прислал код позиции 0 и сумму всех (см. isCartTotalPrice).
  //   Коды из premium_item_map.json и функциональные уже сверены с ценой выше (premium-price-mismatch).
  const cartTotal = subtype === 1 && !premiumMapping && !undeliverable && isCartTotalPrice(itemCode, price);
  const purchase = cart
    ? (cart.error
      ? { status: 0, ...readAccountBalance(account), source: cart.error }
      : { ...purchaseSqlAccount(account, cartExt.codes[0], cart.sum, cart.rows), cart: true })
    : subtype === 2 && !reward
    ? { status: 0, balance: 0, present: 0, source: "missing-luckybox-pool" }
    : unknownReward
    ? { status: 0, ...readAccountBalance(account), source: "unknown-reward-code" }
    : missingPremiumMapping
      ? { status: 0, ...readAccountBalance(account), source: "missing-premium-item-map" }
      : invalidPremiumPrice
        ? { status: 0, ...readAccountBalance(account), source: "premium-price-mismatch" }
        : undeliverable
          ? { status: 0, ...readAccountBalance(account), source: "undeliverable-item-code" }
          : cartTotal
            ? { status: 0, ...readAccountBalance(account), source: "cart-total-mismatch" }
            : purchaseSqlAccount(account, billingItemCode, authoritativePrice);
  if (testFixedBalance() > 0 && purchase.status === 1) {
    purchase.balance = testFixedBalance();   // тестовый режим: после покупки баланс остаётся прежним
  }

  // The GP7 response is the request payload shifted by one byte for status,
  // followed by the authoritative price. GameServer also consumes echoed
  // special-item metadata at response offsets 96..99 (request 95..98).
  //
  // Смещение 174 — это НОМЕР ЗАКАЗА: GameServer читает его как tOrderIndex
  // (GameServer.c:95167 и :95202 — обе ветки, предмет и лаки-бокс), кладёт
  // в смещение 90 DB-пакета 2601, а DBManager передаёт шестым параметром
  // в EXEC UPCashitemBuy, то есть в @Orderidx -> Joy1.dbo.ItemPostbox.Orderidx.
  // Раньше сюда шла цена (premium) или остаток баланса (лаки-бокс): два предмета
  // одной цены получали ОДИН И ТОТ ЖЕ номер заказа, а выдача искала и удаляла
  // строку по этому неуникальному ключу. Теперь пишем id строки журнала покупок
  // dbo.GP7PurchaseLog — он уникален по построению (identity).
  const payload = Buffer.alloc(178, 0);
  frame.payload.copy(payload, 1, 0, Math.min(frame.payload.length, 173));
  payload[0] = purchase.status;
  payload[1] = subtype;
  payload.writeUInt32LE(userIndex, 2);
  const responseItemCode = cart && !cart.error ? cart.rows[0].code : rewardItemCode;
  payload.writeUInt32LE(responseItemCode, 67);
  // GameServer читает смещение 174 как ЗНАКОВЫЙ int, а UPCashitemBuy трактует
  // отрицательный @Orderidx как «сгенерируй свой» — поэтому держим номер
  // в диапазоне 1..2147483647.
  const orderIndex = Number.isSafeInteger(purchase.purchaseId) && purchase.purchaseId > 0
    ? ((purchase.purchaseId - 1) % 2147483647) + 1
    : 0;
  if (subtype === 2) {
    payload[71] = rewardCount;
    payload[104] = 3;
    payload.writeUInt32LE(purchase.balance, 105);
    payload.writeUInt32LE(purchase.present, 109);
    payload.writeUInt32LE(orderIndex, 174);
  } else {
    payload[104] = requestFlag;
    payload.writeUInt32LE(purchase.balance, 105);
    payload.writeUInt32LE(purchase.present, 109);
    payload.writeUInt32LE(orderIndex, 174);
  }

  const response = Buffer.alloc(9 + payload.length + 1, 0);
  response[0] = 0xfb;
  response.writeUInt16LE(response.length, 1);
  response.writeUInt16LE(frame.kind, 3);
  response.writeUInt16LE(frame.route, 5);
  response.writeUInt16LE(0x51, 7);
  payload.copy(response, 9);
  response[response.length - 1] = 0xfe;

  return {
    response,
    account,
    subtype,
    userIndex,
    userNum,
    requestItemCode: itemCode,
    itemCode: responseItemCode,
    rewardIndex: reward ? reward.index : null,
    rewardCount,
    boxType,
    price: cart ? cart.sum : authoritativePrice,
    requestedPrice: price,
    cartCodes: cartExt ? cartExt.codes : null,
    cartDelivery: cart && cart.rows ? cart.rows.map((r) => r.code) : null,
    cartBadCode: cart && cart.code !== undefined ? cart.code : null,
    ...purchase,
    orderIndex,   // ★ 22.11.2026: номер заказа ответа (смещение 174) — в строку журнала SEND 0x0051 и в PURCHASE_UNCONFIRMED
  };
}

// ★★★ 01.11.2026 P101_CashGift — ПОДАРОК ИЗ КЭШ-МАГАЗИНА (проект Reports/cash_gift/PROJECT_P101.md §4, контракт
//   Reports/cash_gift/p101/PROTOCOL_GP7_GIFT.md). [ИСПРАВЛЕНИЕ стока] Сток списывал после ответа получателя (5077) и
//   мимо шлюза (sub_43FC70(…,0,0)). Теперь GameServer с AsdaPatch P101 шлёт запрос 0x52:
//     действие 1 HOLD — проверить цены и заморозить сумму ДО отправки 5076;
//     2 COMMIT — подарок выдан (5077 [0]=1);
//     3 REFUND — не выдан (5077 [0]=0/2).
//   журнал dbo.GP7GiftLog, ключ запроса GS UNIQUE — повтор HOLD не списывает второй раз.
//   Цена позиции = цена витрины (resolvePremiumItem, решение владельца). Сумма запроса обязана совпасть, иначе
//   gift-price-mismatch без списания. Белый список — SellItemTable.txt GameServer-а (то, что продаёт витрина).
const GIFT_REQUEST_BYTES = 157;   // длина payload запроса 0x52
const GIFT_RESPONSE_BYTES = 28;   // длина payload ответа 0x53
const GIFT_ACTION_NAMES = { 1: "GIFT_HOLD", 2: "GIFT_COMMIT", 3: "GIFT_REFUND" };   // действие → метка журнала

let giftSellCodes;   // Set кодов SellItemTable.txt (белый список подарка); null — таблица не прочиталась (подарки отклоняются)
let giftSellRetryAt = 0;   // ★ 02.11 (ревизия М3): когда (Date.now()) повторить чтение, если прошлое не удалось
const GIFT_SELL_RETRY_MS = 30000;   // повтор неудачного чтения не чаще раза в 30 с

// Белый список подарка: коды SellItemTable.txt. Первая строка — «наибольший код  число кодов», дальше коды. Как GameServer,
//   берём ровно объявленное число. Кодов меньше, чем объявлено, или таблицы нет — null: подарок отклоняется
//   (gift-whitelist-unavailable), денег не берём. Перечитывается при изменении файла (fileChanged), а после неудачного
//   чтения (файл занят при копировании) — повторно через GIFT_SELL_RETRY_MS, даже если время и размер файла не менялись.
function loadGiftSellCodes() {
  const tablePath = path.resolve(root, config.giftSellItemTable || "../GameServer/ItemTable_Info/SellItemTable.txt");
  const changed = fileChanged("giftSellItemTable", tablePath);
  if (giftSellCodes !== undefined && !changed && !(giftSellCodes === null && Date.now() >= giftSellRetryAt)) {
    return giftSellCodes;
  }
  giftSellCodes = null;
  giftSellRetryAt = Date.now() + GIFT_SELL_RETRY_MS;
  try {
    const tokens = fs.readFileSync(tablePath, "latin1").trim().split(/\s+/);
    const declared = Number(tokens[1]);
    const codes = tokens.slice(2, 2 + declared);
    if (tokens.length < 2 || !Number.isInteger(declared) || declared <= 0 || codes.length !== declared ||
        codes.some((t) => !/^\d+$/.test(t))) {
      throw new Error(`bad table: declared=${tokens[1]} parsed=${codes.length}`);
    }
    giftSellCodes = new Set(codes.map(Number));
    writeLog(`GIFT_SELL_TABLE_OK file=${JSON.stringify(tablePath)} rows=${declared} unique=${giftSellCodes.size}`);
  } catch (err) {
    writeLog(`GIFT_SELL_TABLE_ERROR file=${JSON.stringify(tablePath)} ${err.message}`);
  }
  return giftSellCodes;
}

// Поле фиксированной длины до первого NUL — сырыми байтами (имена в кодовой странице игры, в SQL идут как 0x…).
function readFixedBytes(payload, offset, length) {
  const field = payload.subarray(offset, offset + length);
  const terminator = field.indexOf(0);
  return Buffer.from(field.subarray(0, terminator < 0 ? field.length : terminator));
}

// Позиции подарка → { units, sum } или { error, code, sum }. Позиции идут подряд с первой (0 = конец списка):
//   нет ни одной или после 0 снова код — gift-bad-request. Каждая позиция: белый список, затем цена витрины.
function resolveGiftCodes(codes, amount) {
  const used = codes.filter((c) => c !== 0);
  const firstZero = codes.indexOf(0);
  if (used.length === 0 || (firstZero >= 0 && codes.slice(firstZero).some((c) => c !== 0))) {
    return { error: "gift-bad-request", code: null, sum: 0 };
  }
  const sell = loadGiftSellCodes();
  if (!sell) {
    return { error: "gift-whitelist-unavailable", code: null, sum: 0 };
  }
  const units = [];
  let sum = 0;
  for (const code of used) {
    if (!sell.has(code)) {
      return { error: "gift-code-not-on-sale", code, sum };
    }
    const r = resolvePremiumItem(code, { ignoreDelivery: true });
    if (r.error) {
      return { error: "gift-unknown-item-price", code, sum, detail: r.error };
    }
    units.push(r.unit);
    sum += r.unit;
  }
  if (sum !== amount) {
    return { error: "gift-price-mismatch", code: null, sum, units };
  }
  return { units, sum };
}

// Запуск sqlcmd для подарка → { status, balance, present, orderId, reason, state } (одна строка процедуры GP7_Gift*).
//   Ошибка sqlcmd / тайм-аут / неожиданный ответ — status 0, reason sql-error. ★ 02.11 (ревизия В2): исход при этом НЕИЗВЕСТЕН —
//   при тайм-ауте execFileSync убивает клиент, а транзакция на сервере могла уже закоммититься. Поэтому giftHold/giftSettle
//   при sql-error не отвечают «денег нет», а перечитывают заказ (giftRecover).
function runGiftSql(query, what) {
  const sql = config.sql || {};
  try {
    const output = execFileSync(sql.command || "SQLCMD.EXE", [
      "-S", sql.server || "@@ASTORY_SERVER_LAN_IP@@",
      "-E",
      "-C",
      "-d", sql.database || "AsdaStoryLogin",
      "-b",
      "-h", "-1",
      "-W",
      "-s", "|",
      "-Q", query,
    ], {
      encoding: "utf8",
      timeout: Number(sql.timeoutMs || 5000),
      windowsHide: true,
    });
    const row = output.split(/\r?\n/).map((line) => line.trim())
      .find((line) => /^[0-5]\|-?\d+\|\d+\|\d+\|[a-z-]+\|[HCR-]$/.test(line));
    if (!row) {
      throw new Error(`Unexpected sqlcmd response: ${JSON.stringify(output.trim())}`);
    }
    const f = row.split("|");
    return {
      status: Number(f[0]),
      balance: Math.max(0, Number(f[1])) >>> 0,
      present: Number(f[2]) >>> 0,
      orderId: Number(f[3]),
      reason: f[4],
      state: f[5],
    };
  } catch (err) {
    writeLog(`SQL_GIFT_ERROR op=${what} ${err.message}`);
    return { status: 0, balance: 0, present: 0, orderId: 0, reason: "sql-error", state: "-" };
  }
}

// ★ 02.11 (ревизия В2): исход HOLD/settle после sql-error — перечитать заказ ТОЛЬКО ЧТЕНИЕМ (dbo.GP7_GiftLookup) и ответить
//   фактом. HOLD: заказ 'H' с этим ключом → status 1 'recovered'; уже 'C'/'R' → 3 'wrong-state'; ключ у чужого заказа → 0
//   'key-conflict'; заказа нет или чтение тоже не удалось → 5 'unknown' (GS повторяет HOLD ТЕМ ЖЕ ключом: GP7_GiftHold под
//   UPDLOCK/HOLDLOCK ответит repeat или выполнит заморозку один раз). Settle: state = цель → 1 'recovered'; ещё 'H' или чтение
//   не удалось → 5 'unknown' (повтор settle идемпотентен); другой исход → 3; заказа нет / чужой → 4.
function giftRecover(g) {
  const key = g.action === 1 ? `@gs_key=0x${toHex(g.key)}` : `@order_id=${g.orderIdx}`;
  const look = runGiftSql(`SET NOCOUNT ON; EXEC dbo.GP7_GiftLookup ${key}, @username='${sqlString(g.account)}', ` +
    `@amount=${g.amount};`, "lookup");
  const unknown = { ...look, status: 5, reason: "unknown", orderId: look.orderId || 0, state: look.state || "-" };
  if (look.reason === "sql-error") {
    return unknown;
  }
  if (look.reason === "not-found") {
    return g.action === 1 ? unknown : { ...look, status: 4, reason: "order-not-found" };
  }
  if (look.reason === "order-mismatch") {
    return g.action === 1 ? { ...look, status: 0, orderId: 0, reason: "key-conflict" } : { ...look, status: 4 };
  }
  const target = g.action === 1 ? "H" : g.action === 2 ? "C" : "R";
  if (look.state === target) {
    return { ...look, status: 1, reason: "recovered" };
  }
  if (g.action !== 1 && look.state === "H") {
    return unknown;
  }
  return { ...look, status: 3, reason: "wrong-state" };
}

// HOLD: проверка цен и белого списка, затем GP7_GiftHold (тестовый режим — @test_topup=1, пополнение на сумму внутри транзакции).
//   ★ 02.11 (ревизия М2): проверка «подарок себе» перенесена в GP7_GiftHold — сравнение имён как у процедур Joy1 (fn_AsdaNameEq).
function giftHold(g) {
  if (!g.account || Buffer.byteLength(g.account, "utf8") > 50 || g.amount <= 0 || g.recipientRaw.length === 0) {
    return { status: 0, ...readAccountBalance(g.account), orderId: 0, source: "gift-bad-request", state: "-" };
  }
  const priced = resolveGiftCodes(g.codes, g.amount);
  if (priced.error) {
    return { status: 0, ...readAccountBalance(g.account), orderId: 0, source: priced.error, state: "-",
      priceSum: priced.sum, badCode: priced.code, priceDetail: priced.detail };
  }
  const c = g.codes.map((x) => Number(x));
  const query = `SET NOCOUNT ON; ${siteUserProvisionSql(g.account)}EXEC dbo.GP7_GiftHold ` +
    `@username='${sqlString(g.account)}', @gs_key=0x${toHex(g.key)}, @userindex=${g.userIndex | 0}, ` +
    `@charidx=${g.charIdx | 0}, @usernum=${g.userNum}, @sender_name=0x${toHex(g.senderRaw)}, ` +
    `@recipient_name=0x${toHex(g.recipientRaw)}, @code1=${c[0]}, @code2=${c[1]}, @code3=${c[2]}, @code4=${c[3]}, ` +
    `@code5=${c[4]}, @code6=${c[5]}, @code7=${c[6]}, @amount=${g.amount}, @test_topup=${testFixedBalance() > 0 ? 1 : 0};`;
  let r = runGiftSql(query, "hold");
  if (r.reason === "sql-error") {
    r = giftRecover(g);
  }
  return { ...r, source: `gift-${r.reason}`, priceSum: priced.sum, units: priced.units };
}

// COMMIT / REFUND: GP7_GiftSettle со сверкой учётки, суммы и ключа HOLD. Возврат денег заказа test_mode=1 процедура не делает.
//   sql-error → giftRecover (исход перечитывается, «неизвестно» = status 5).
function giftSettle(g) {
  if (!g.account || Buffer.byteLength(g.account, "utf8") > 50) {
    return { status: 0, ...readAccountBalance(g.account), orderId: 0, source: "gift-bad-request", state: "-" };
  }
  const query = `SET NOCOUNT ON; EXEC dbo.GP7_GiftSettle @order_id=${g.orderIdx}, @action=${g.action}, ` +
    `@username='${sqlString(g.account)}', @amount=${g.amount}, @gs_key=0x${toHex(g.key)}, @settle_result=${g.result5077};`;
  let r = runGiftSql(query, g.action === 2 ? "commit" : "refund");
  if (r.reason === "sql-error") {
    r = giftRecover(g);
  }
  return { ...r, source: `gift-${r.reason}` };
}

// Запрос подарка 0x52 → { response (кадр 0x53), поля запроса g, результат r, orderIndex } или null, если кадр не 0x52 / короче
//   157 б. Раскладки — PROTOCOL_GP7_GIFT.md §2/§3. Действие 1 → giftHold, 2/3 → giftSettle, иное → отказ gift-bad-action.
function buildGiftResponse(request) {
  const frame = readFrame(request);
  if (!frame || frame.command !== 0x52 || frame.payload.length < GIFT_REQUEST_BYTES) {
    return null;
  }

  // Раскладка запроса — PROTOCOL_GP7_GIFT.md §2.
  const p = frame.payload;
  const g = {
    action: p[0],
    userIndex: p.readUInt32LE(1),
    account: readFixedText(p, 5, 61),
    charIdx: p.readUInt32LE(66),
    userNum: p.readUInt16LE(70),
    senderRaw: readFixedBytes(p, 72, 20),
    recipientRaw: readFixedBytes(p, 92, 20),
    codes: Array.from({ length: 7 }, (_, i) => p.readUInt32LE(112 + 4 * i)),
    amount: p.readUInt32LE(140),
    orderIdx: p.readUInt32LE(144),
    key: Buffer.from(p.subarray(148, 156)),
    result5077: p[156],
  };

  const r = g.action === 1
    ? giftHold(g)
    : (g.action === 2 || g.action === 3)
      ? giftSettle(g)
      : { status: 0, ...readAccountBalance(g.account), orderId: 0, source: "gift-bad-action", state: "-" };
  if (testFixedBalance() > 0 && g.account) {
    r.balance = testFixedBalance();   // тестовый режим: баланс в ответе всегда фиксированный, как у покупки
  }
  // Номер заказа в ответе — как 0x51 [174]: id журнала, приведённый к 1..2147483647 (GameServer читает знаковый int).
  const orderIndex = Number.isSafeInteger(r.orderId) && r.orderId > 0 ? ((r.orderId - 1) % 2147483647) + 1 : 0;

  // Раскладка ответа — PROTOCOL_GP7_GIFT.md §3.
  const payload = Buffer.alloc(GIFT_RESPONSE_BYTES, 0);
  payload[0] = r.status;
  payload[1] = g.action;
  payload.writeUInt32LE(g.userIndex, 2);
  payload.writeUInt16LE(g.userNum, 6);
  payload.writeUInt32LE(orderIndex, 8);
  payload.writeUInt32LE(r.balance >>> 0, 12);
  payload.writeUInt32LE(r.present >>> 0, 16);
  g.key.copy(payload, 20);

  const response = Buffer.alloc(9 + payload.length + 1, 0);
  response[0] = 0xfb;
  response.writeUInt16LE(response.length, 1);
  response.writeUInt16LE(frame.kind, 3);
  response.writeUInt16LE(frame.route, 5);
  response.writeUInt16LE(0x53, 7);
  payload.copy(response, 9);
  response[response.length - 1] = 0xfe;

  return { response, ...g, ...r, orderIndex };
}

// ★★★ 05.11.2026 ОТВЕТ НА ПИНГ И НА ПРИВЕТСТВИЕ GameServer (баг игроков «гача: списали — не выдали»). [ИСПРАВЛЕНИЕ шлюза]
//   GameServer раз в 5 с шлёт узлу 93 (GP7) кадр-пинг команды 20 (0x14, `FB 0A00 0000 5D00 1400 FE`) и ждёт ответ
//   команды 21 (0x15): только она обновляет время последнего ответа (GameServer.c:9785-9788, case 21 → dword_5E2C04).
//   Если 180 000 мс (0x2BF20) ответа 21 нет, GameServer РВЁТ связь и переподключается (GameServer.c:9017-9033,
//   «Arab Ping Timeout. Try to Reconnect»). Прежний шлюз (mode "echo") возвращал пинг как есть — командой 20, которую
//   GameServer молча пропускает (`default: return`), поэтому связь рвалась каждые 3 минуты (~475 раз в сутки на канал,
//   Log_AliveCheck\Ping_*.txt). Ответ 0x51 на покупку, попавший в момент обрыва, уходил в старый сокет: GP7 списал, а
//   GameServer запись в элитный ящик не сделал (01.11 19:40:41, заказ 15068 — ровно секунда переподключения).
//   Приветствие после (пере)подключения — команда 10 (0x0A, 32 б); ответ — команда 11 (0x0B), байт [0] = 0 «Success»
//   (GameServer.c:9773-9783, иначе в журнале «Arab ConnectInit Result Failure»).
//   Шапка ответа (kind, route) — как у прочих ответов шлюза: из запроса. Отключение — config.answerAlivePing = false.
const GS_CMD_PING = 0x14;          // команда пинга GameServer → GP7
const GS_CMD_PING_ACK = 0x15;      // ответ на пинг (GameServer ждёт именно её)
const GS_CMD_CONNECT_INIT = 0x0a;  // приветствие GameServer после подключения
const GS_CMD_CONNECT_ACK = 0x0b;   // ответ на приветствие, payload[0] = 0 — успех
function buildAliveResponse(request) {
  if (config.answerAlivePing === false) {
    return null;
  }
  const frame = readFrame(request);
  if (!frame || (frame.command !== GS_CMD_PING && frame.command !== GS_CMD_CONNECT_INIT)) {
    return null;
  }
  const isPing = frame.command === GS_CMD_PING;
  const payload = isPing ? Buffer.alloc(0) : Buffer.alloc(1, 0);   // ConnectInit: [0] = 0 «Success»
  const response = Buffer.alloc(9 + payload.length + 1, 0);
  response[0] = 0xfb;
  response.writeUInt16LE(response.length, 1);
  response.writeUInt16LE(frame.kind, 3);
  response.writeUInt16LE(frame.route, 5);
  response.writeUInt16LE(isPing ? GS_CMD_PING_ACK : GS_CMD_CONNECT_ACK, 7);
  payload.copy(response, 9);
  response[response.length - 1] = 0xfe;
  return { response, isPing };
}

// ★ 22.11.2026 [ИСПРАВЛЕНИЕ] «оплачено, но не выдано» (research_gp7_orphan_orders_20261121.md, причина B, заказ 15068):
//   списание фиксируется в GP7_Purchase ДО того, как GameServer получил ответ. Если сокет GameServer закрылся или дал ошибку в
//   течение config.purchaseUnconfirmedMs (по умолчанию 2000 мс) после ответа status 1 — ответ мог не дойти. Тогда в журнал
//   шлюза пишется строка PURCHASE_UNCONFIRMED с номером заказа (её читает сверка «Оплачено, не выдано» панели). Шлюз ничего
//   не откатывает: решение по заказу принимает человек. 0 — отметки нет (как раньше).
function purchaseUnconfirmedMs() {
  const v = config.purchaseUnconfirmedMs === undefined ? 2000 : Number(config.purchaseUnconfirmedMs);
  return Number.isFinite(v) && v > 0 ? v : 0;
}

// Запомнить ответ status 1 на покупку у сокета (socket.gp7Pending — только ответы моложе окна).
function trackPurchase(socket, purchase) {
  const ms = purchaseUnconfirmedMs();
  if (ms === 0 || purchase.status !== 1) {
    return;
  }
  const now = Date.now();
  socket.gp7Pending = (socket.gp7Pending || []).filter((x) => now - x.at <= ms);
  socket.gp7Pending.push({
    at: now, order: purchase.orderIndex, account: purchase.account, subtype: purchase.subtype,
    itemCode: purchase.itemCode, price: purchase.price,
  });
}

// Сокет закрылся / ошибка / запись не удалась: ответы моложе окна → PURCHASE_UNCONFIRMED (по строке на заказ), список очищается.
function flagUnconfirmed(socket, remote, reason) {
  const ms = purchaseUnconfirmedMs();
  const now = Date.now();
  for (const x of socket.gp7Pending || []) {
    if (ms > 0 && now - x.at <= ms) {
      writeLog(
        `PURCHASE_UNCONFIRMED ${remote} order=${x.order} account=${JSON.stringify(x.account)} subtype=${x.subtype} ` +
        `itemCode=${x.itemCode} price=${x.price} afterMs=${now - x.at} reason=${reason}`
      );
    }
  }
  socket.gp7Pending = [];
}

function sendResponse(socket, remote, data) {
  // ★ 05.11.2026: пинг и приветствие GameServer — ответ 0x15 / 0x0B вместо эха (описание — у buildAliveResponse).
  const alive = buildAliveResponse(data);
  if (alive) {
    socket.write(alive.response);
    if (alive.isPing && config.quietHeartbeat) {
      writeLog(`SEND ${remote} heartbeat-ack bytes=${alive.response.length}`);
    } else {
      writeLog(`SEND ${remote} bytes=${alive.response.length} command=0x00${alive.isPing ? "15" : "0B"} hex=${toHex(alive.response)}`);
    }
    return;
  }

  const balance = buildBalanceResponse(data);
  if (balance) {
    socket.write(balance.response);
    writeLog(
      `SEND ${remote} bytes=${balance.response.length} command=0x005B ` +
      `account=${JSON.stringify(balance.account)} source=${balance.source} found=${balance.found} ` +
      `userIndex=${balance.userIndex} userNum=${balance.userNum} ` +
      `balance=${balance.balance} present=${balance.present} ` +
      `hex=${toHex(balance.response)}`
    );
    return;
  }

  const purchase = buildPurchaseResponse(data);
  if (purchase) {
    // ★ 22.11.2026: ответ на покупку ждёт подтверждения «сокет не закрылся» (trackPurchase / flagUnconfirmed); ошибка самой записи —
    //   тоже отметка PURCHASE_UNCONFIRMED. Байты ответа и порядок записи прежние.
    socket.write(purchase.response, (err) => {
      if (err) {
        flagUnconfirmed(socket, remote, `write-error:${err.code || err.message}`);
      }
    });
    trackPurchase(socket, purchase);
    writeLog(
      `SEND ${remote} bytes=${purchase.response.length} command=0x0051 ` +
      `account=${JSON.stringify(purchase.account)} source=${purchase.source} status=${purchase.status} order=${purchase.orderIndex} ` +
      `subtype=${purchase.subtype} userIndex=${purchase.userIndex} userNum=${purchase.userNum} ` +
      `requestItemCode=${purchase.requestItemCode} itemCode=${purchase.itemCode} ` +
      `rewardIndex=${purchase.rewardIndex} rewardCount=${purchase.rewardCount} ` +
      `requestedPrice=${purchase.requestedPrice} price=${purchase.price} ` +
      (purchase.source === "cart-total-mismatch" ? `unitPrice=${loadItemTablePrices().get(purchase.requestItemCode)} ` : "") +
      (purchase.cartCodes ? `cart=${purchase.cartCodes.join(",")} ` : "") +
      (purchase.cartDelivery ? `cartDelivery=${purchase.cartDelivery.join(",")} ` : "") +
      (purchase.cartBadCode !== null && purchase.cartBadCode !== undefined ? `cartBadCode=${purchase.cartBadCode} ` : "") +
      `balance=${purchase.balance} present=${purchase.present} ` +
      `hex=${toHex(purchase.response)}`
    );
    return;
  }

  // ★ 01.11.2026 P101_CashGift: запрос подарка 0x52 → ответ 0x53 (строка журнала GIFT_HOLD / GIFT_COMMIT / GIFT_REFUND).
  const gift = buildGiftResponse(data);
  if (gift) {
    socket.write(gift.response);
    writeLog(
      `${GIFT_ACTION_NAMES[gift.action] || "GIFT_BAD_ACTION"} ${remote} bytes=${gift.response.length} command=0x0053 ` +
      `account=${JSON.stringify(gift.account)} order=${gift.orderIndex} recipient=${JSON.stringify(gift.recipientRaw.toString("latin1"))} ` +
      `recipientHex=${toHex(gift.recipientRaw)} sender=${JSON.stringify(gift.senderRaw.toString("latin1"))} ` +
      `userIndex=${gift.userIndex} charIdx=${gift.charIdx} userNum=${gift.userNum} codes=${gift.codes.join(",")} ` +
      `amount=${gift.priceSum !== undefined ? gift.priceSum : gift.amount} requestedAmount=${gift.amount} ` +
      `status=${gift.status} source=${gift.source} state=${gift.state} ` +
      (gift.badCode !== null && gift.badCode !== undefined ? `badCode=${gift.badCode} ` : "") +
      (gift.priceDetail ? `priceDetail=${gift.priceDetail} ` : "") +
      (gift.units ? `units=${gift.units.join(",")} ` : "") +
      `result5077=${gift.result5077} requestOrder=${gift.orderIdx} key=${toHex(gift.key)} ` +
      `balance=${gift.balance} present=${gift.present} hex=${toHex(gift.response)}`
    );
    return;
  }

  if (config.mode === "echo") {
    socket.write(data);
    writeLog(`SEND ${remote} bytes=${data.length} mode=echo`);
  }
}

const server = net.createServer((socket) => {
  const remote = `${socket.remoteAddress}:${socket.remotePort}`;
  let pending = Buffer.alloc(0);
  socket.setKeepAlive(true, 10000);
  writeLog(`ACCEPT ${remote}`);

  socket.on("data", (data) => {
    pending = Buffer.concat([pending, data]);

    while (pending.length >= 3) {
      if (pending[0] !== 0xfb) {
        writeLog(`DROP ${remote} reason=invalid-start byte=${pending[0].toString(16).padStart(2, "0")}`);
        pending = pending.subarray(1);
        continue;
      }

      const frameLength = pending.readUInt16LE(1);
      if (frameLength < 10 || frameLength > 0x10000) {
        writeLog(`DROP ${remote} reason=invalid-length length=${frameLength}`);
        pending = pending.subarray(1);
        continue;
      }
      if (pending.length < frameLength) {
        break;
      }

      const frameData = pending.subarray(0, frameLength);
      pending = pending.subarray(frameLength);
      const frame = readFrame(frameData);
      const isHeartbeat = toHex(frameData) === String(config.heartbeatHex || "").toUpperCase();

      if (isHeartbeat && config.quietHeartbeat) {
        writeLog(`RECV ${remote} heartbeat bytes=${frameData.length}`);
      } else {
        writeLog(
          `RECV ${remote} bytes=${frameData.length} command=${frame ? `0x${frame.command.toString(16).padStart(4, "0").toUpperCase()}` : "invalid"}\n` +
          hexDump(frameData, config.logBytes || 512)
        );
      }
      sendResponse(socket, remote, frameData);
    }
  });

  socket.on("error", (err) => {
    writeLog(`SOCKET_ERROR ${remote} ${err.message}`);
    flagUnconfirmed(socket, remote, `socket-error:${err.code || err.message}`);   // ★ 22.11.2026
  });

  socket.on("close", () => {
    writeLog(`CLOSE ${remote}`);
    flagUnconfirmed(socket, remote, "close");                                        // ★ 22.11.2026
  });
});

server.on("error", (err) => {
  console.error(`[GP7] ${err.message}`);
  writeLog(`SERVER_ERROR ${err.message}`);
  process.exitCode = 1;
});

try {
  installSqlSchema();
  server.listen(config.port, config.host, () => {
    const msg = `[GP7] listening on ${config.host}:${config.port}`;
    console.log(msg);
    writeLog(msg);
  });
} catch (err) {
  console.error(`[GP7] SQL migration failed: ${err.message}`);
  process.exitCode = 1;
}
