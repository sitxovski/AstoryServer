// Copyright (c) 2026 @sitxovski (Discord)
// Стенд шлюза gp7: прогоняет ВСЕ исторические запросы покупки 0x0050 из журналов gp7 через новый server.js
// (локально, SQL недоступен → «billing reached» = source sql-error) и сверяет решение с прежним.
// argv: <stand gp7-server dir> <logs dir> <port>
"use strict";
const fs = require("fs");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");

const standDir = process.argv[2];
const logsDir = process.argv[3];
const port = Number(process.argv[4] || 25022);

// 1) Извлечь пары (кадр запроса, прежнее решение) из журналов.
const cases = [];
for (const f of fs.readdirSync(logsDir).filter((n) => /^gp7-\d+\.log$/.test(n)).sort()) {
  const lines = fs.readFileSync(path.join(logsDir, f), "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; ++i) {
    if (!/ RECV .* command=0x0050$/.test(lines[i])) continue;
    const bytes = [];
    let j = i + 1;
    while (j < lines.length && /^[0-9a-f]{4}  /.test(lines[j])) {
      const hex = lines[j].slice(6, 6 + 47).trim();
      for (const h of hex.split(/\s+/)) if (h) bytes.push(parseInt(h, 16));
      ++j;
    }
    // прежний ответ — ближайшая следующая строка SEND command=0x0051
    let old = null;
    for (let k = j; k < Math.min(lines.length, j + 6); ++k) {
      if (/command=0x0051/.test(lines[k])) { old = lines[k]; break; }
    }
    const buf = Buffer.from(bytes);
    if (buf.length !== buf.readUInt16LE(1)) continue;   // дамп обрезан — пропускаем
    cases.push({ file: f, ts: lines[i].slice(0, 23), buf, old });
  }
}
console.log(`cases=${cases.length}`);

// 2) Поднять стенд.
const child = spawn(process.execPath, [path.join(standDir, "server.js")], { cwd: standDir, stdio: ["ignore", "pipe", "pipe"] });
child.stderr.on("data", (d) => process.stderr.write(d));

function field(line, name) {
  const m = line && line.match(new RegExp(` ${name}=("[^"]*"|\\S+)`));
  return m ? m[1].replace(/"/g, "") : null;
}

function run() {
  const sock = net.connect(port, "127.0.0.1");
  let pending = Buffer.alloc(0);
  let idx = 0;
  const results = [];
  sock.on("data", (d) => {
    pending = Buffer.concat([pending, d]);
    while (pending.length >= 3 && pending.length >= pending.readUInt16LE(1)) {
      const len = pending.readUInt16LE(1);
      const frame = pending.subarray(0, len);
      pending = pending.subarray(len);
      results.push(frame);
      ++idx;
      if (idx < cases.length) sock.write(cases[idx].buf); else sock.end();
    }
  });
  sock.on("end", () => finish(results));
  sock.on("connect", () => sock.write(cases[0].buf));
}

function finish(results) {
  // решение стенда — из его журнала (source), по порядку
  const standLogDir = path.join(standDir, "logs");
  const sends = [];
  for (const f of fs.readdirSync(standLogDir).sort()) {
    for (const l of fs.readFileSync(path.join(standLogDir, f), "utf8").split(/\r?\n/)) {
      if (/command=0x0051/.test(l)) sends.push(l);
    }
  }
  const tally = {};
  let changed = 0;
  for (let i = 0; i < cases.length; ++i) {
    const c = cases[i];
    const nw = sends[i];
    const oldSrc = field(c.old, "source"), newSrc = field(nw, "source");
    const oldSt = field(c.old, "status"), newSt = nw ? String(results[i][9]) : null;
    // «прошло к списанию» прежде = status 1 (sql), теперь = sql-error (SQL на стенде нет)
    const oldBill = oldSrc === "sql";
    const newBill = newSrc === "sql-error";
    const key = `${oldBill ? "bill" : "rej:" + oldSrc} -> ${newBill ? "bill" : "rej:" + newSrc}`;
    tally[key] = (tally[key] || 0) + 1;
    if (oldBill !== newBill || (!oldBill && oldSrc !== newSrc)) {
      ++changed;
      console.log(`CHANGED ${c.ts} account=${field(c.old, "account")} subtype=${field(c.old, "subtype")} code=${field(c.old, "requestItemCode")} ` +
        `req=${field(c.old, "requestedPrice")} unit=${field(nw, "unitPrice")} old=${oldSrc}/${oldSt} new=${newSrc}/${newSt}`);
    }
  }
  console.log("TALLY", JSON.stringify(tally, null, 1));
  console.log(`changed=${changed} of ${cases.length}`);
  child.kill();
}

let started = false;
child.stdout.on("data", (d) => {
  process.stdout.write(`[stand] ${d}`);
  if (!started && /listening/.test(String(d))) { started = true; run(); }
});
