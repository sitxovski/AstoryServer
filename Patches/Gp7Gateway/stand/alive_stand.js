// Copyright (c) 2026 @sitxovski (Discord)
// ★ 05.11.2026 Стенд ответа шлюза gp7 на пинг (0x14 → 0x15) и приветствие (0x0A → 0x0B) GameServer.
//   Зачем: GameServer рвёт связь с GP7, если 180 с не получает команду 21 (GameServer.c:9017-9033, :9785-9788); прежний шлюз
//   отвечал на пинг эхом (команда 20) → обрыв каждые 3 минуты и потеря ответа 0x51 на покупку, попавшую в обрыв.
//   Что делает: копирует ../server.js в %TEMP%\gp7alive_stand\{on,off}, пишет config.json (balanceSource "json" — без SQL),
//   поднимает два экземпляра и проверяет кадры так, как их разбирает GameServer:
//     P1 пинг `FB 0A00 0000 5D00 1400 FE` → ровно 10 б, команда 0x15, kind/route из запроса, хвост 0xFE;
//     P2 приветствие (команда 0x0A, 32 б полезной нагрузки, как sub_5646C0(…, 10, 32, 93, …)) → команда 0x0B, payload[0] = 0;
//     P3 три пинга одним пакетом TCP (склейка) → три ответа 0x15;
//     P4 запрос баланса 0x5A → ответ 0x5B (прежний путь не задет);
//     K0 config.answerAlivePing = false → пинг возвращается эхом 0x14 (прежнее поведение).
//   argv: [порт on] [порт off]. Итог: «GP7-ALIVE ИТОГ: ok=N fail=M», код возврата 0/1.
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");

const portOn = Number(process.argv[2] || 25061);     // экземпляр с ответом на пинг
const portOff = Number(process.argv[3] || 25062);    // экземпляр с answerAlivePing = false
const work = path.join(os.tmpdir(), "gp7alive_stand");   // рабочий каталог стенда
let ok = 0;                                          // пройдено
let fail = 0;                                        // провалено

function expect(cond, what) {
  if (cond) { ++ok; console.log(`GP7-ALIVE ok   ${what}`); } else { ++fail; console.log(`GP7-ALIVE FAIL ${what}`); }
}

// Кадр GameServer → GP7: FB, длина u16, kind u16, route u16 (узел 93 = 0x5D), команда u16, payload, FE.
function frame(cmd, payload, kind = 0, route = 0x5d) {
  const b = Buffer.alloc(9 + payload.length + 1, 0);
  b[0] = 0xfb; b.writeUInt16LE(b.length, 1); b.writeUInt16LE(kind, 3); b.writeUInt16LE(route, 5); b.writeUInt16LE(cmd, 7);
  payload.copy(b, 9); b[b.length - 1] = 0xfe;
  return b;
}

// Разобрать поток ответов на кадры.
function split(buf) {
  const out = [];
  let p = 0;
  while (p + 3 <= buf.length && buf[p] === 0xfb) {
    const n = buf.readUInt16LE(p + 1);
    if (n < 10 || p + n > buf.length) break;
    const f = buf.subarray(p, p + n);
    out.push({ len: n, kind: f.readUInt16LE(3), route: f.readUInt16LE(5), cmd: f.readUInt16LE(7), payload: f.subarray(9, n - 1), tail: f[n - 1] });
    p += n;
  }
  return out;
}

// Поднять экземпляр шлюза с данным конфигом.
function startGateway(dir, port, extra) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(path.join(__dirname, "..", "server.js"), path.join(dir, "server.js"));
  const cfg = Object.assign({
    host: "127.0.0.1", port, logBytes: 64, mode: "echo", balanceSource: "json", balancesFile: "balances.json",
    defaultPremiumBalance: 0, defaultPremiumPresent: 0, quietHeartbeat: true, heartbeatHex: "FB0A0000005D001400FE",
  }, extra);
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify(cfg, null, 2));
  fs.writeFileSync(path.join(dir, "balances.json"), "{}");
  const child = spawn(process.execPath, [path.join(dir, "server.js")], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  child.stderr.on("data", (d) => process.stderr.write(d));
  return new Promise((resolve) => {
    child.stdout.on("data", (d) => { if (String(d).includes("listening")) resolve(child); });
    setTimeout(() => resolve(child), 3000);
  });
}

// Отправить байты и собрать ответ за `ms` мс.
function exchange(port, data, ms = 600) {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    let got = Buffer.alloc(0);
    s.on("connect", () => s.write(data));
    s.on("data", (d) => { got = Buffer.concat([got, d]); });
    s.on("error", () => resolve(got));
    setTimeout(() => { s.destroy(); resolve(got); }, ms);
  });
}

async function main() {
  const on = await startGateway(path.join(work, "on"), portOn, {});
  const off = await startGateway(path.join(work, "off"), portOff, { answerAlivePing: false });
  try {
    const ping = Buffer.from("FB0A0000005D001400FE", "hex");
    let r = split(await exchange(portOn, ping));
    expect(r.length === 1 && r[0].len === 10 && r[0].cmd === 0x15 && r[0].kind === 0 && r[0].route === 0x5d && r[0].tail === 0xfe,
      `P1 пинг → ${JSON.stringify(r.map((f) => ({ len: f.len, cmd: f.cmd, kind: f.kind, route: f.route })))} (ждём 10 б, cmd 0x15, route 0x5D)`);

    const init = frame(0x0a, Buffer.alloc(32, 0x11));
    r = split(await exchange(portOn, init));
    expect(r.length === 1 && r[0].cmd === 0x0b && r[0].payload.length >= 1 && r[0].payload[0] === 0 && r[0].route === 0x5d,
      `P2 приветствие 0x0A → ${JSON.stringify(r.map((f) => ({ cmd: f.cmd, p0: f.payload[0], route: f.route })))} (ждём cmd 0x0B, [0]=0)`);

    r = split(await exchange(portOn, Buffer.concat([ping, ping, ping])));
    expect(r.length === 3 && r.every((f) => f.cmd === 0x15), `P3 три пинга одним пакетом → ответов ${r.length}, команды ${r.map((f) => f.cmd).join(",")}`);

    const bal = Buffer.alloc(67, 0);
    Buffer.from("standacc", "latin1").copy(bal, 0);
    bal.writeInt32LE(75214, 61);
    bal.writeInt16LE(3, 65);
    r = split(await exchange(portOn, frame(0x5a, bal)));
    expect(r.length === 1 && r[0].cmd === 0x5b, `P4 баланс 0x5A → ${JSON.stringify(r.map((f) => f.cmd))} (ждём 0x5B, прежний путь)`);

    r = split(await exchange(portOff, ping));
    expect(r.length === 1 && r[0].cmd === 0x14, `K0 answerAlivePing=false → пинг ${JSON.stringify(r.map((f) => f.cmd))} (ждём эхо 0x14)`);
  } finally {
    on.kill(); off.kill();
  }
  console.log(`GP7-ALIVE ИТОГ: ok=${ok} fail=${fail}`);
  process.exitCode = fail ? 1 : 0;
}

main();
