import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { REGISTRY, rpc } from "./wrench.mjs";

const LIVE = process.env.WRENCH_URL ?? "https://near-wrench.nearlive.workers.dev";
const DEMO = "wrenchauditdemo1113.wrenchaudit1113.testnet";
const EVIDENCE = [
  { name: "success verify() on the registry", hash: "DU2JDSeSUx7kc8MHN1ADDkqz2LyW9PMpsY7PRDZVQbQV", ok: true },
  { name: "wallet-path verify() on the registry", hash: "CgS9yrwjzRUeoHo2kxuagRpoVckzK6M69bTBEPtgjvzN", ok: true },
  { name: "tampered receipt refused by verify()", hash: "7fcG8P6AV3Z8wYHP8j8JH1HRGViSiCqrdnuUdkG2tKfa", ok: false },
];

const results = [];
async function check(name, run) {
  if (process.env.JUDGE_ONLY && !name.includes(process.env.JUDGE_ONLY)) return;
  const started = Date.now();
  try { const detail = await run(); results.push({ name, pass: true, detail, ms: Date.now() - started }); }
  catch (error) { results.push({ name, pass: false, detail: error.message.split("\n")[0], ms: Date.now() - started }); }
}
const readStream = async response => {
  const events = [];
  for (const line of (await response.text()).split("\n")) if (line.trim()) events.push(JSON.parse(line));
  return events;
};

await check("offline tests: NEP-413, tx encoding, RPC fallover", () => {
  const run = spawnSync("node", [new URL("./test.mjs", import.meta.url).pathname], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr.trim() || run.stdout.trim());
  return `${run.stdout.split("\n").filter(l => l.startsWith("PASS")).length} PASS lines`;
});

await check("live page serves the app and reports health", async () => {
  const html = await (await fetch(`${LIVE}/`)).text();
  assert.match(html, /Audit your wallet privately/);
  const health = await (await fetch(`${LIVE}/api/health`)).json();
  assert.equal(health.ok, true);
  return `demo account ${health.demo_account}`;
});

await check("link card: og tags and a 1200x630 PNG from our origin", async () => {
  const html = await (await fetch(`${LIVE}/`)).text();
  for (const tag of ["og:title", "og:description", "og:image", "twitter:card"]) assert.ok(html.includes(`"${tag}"`), `missing ${tag}`);
  const image = new URL(html.match(/property="og:image" content="([^"]+)"/)[1]);
  const response = await fetch(`${LIVE}${image.pathname}`);
  assert.equal(response.headers.get("content-type"), "image/png");
  const png = Buffer.from(await response.arrayBuffer());
  assert.equal(png.readUInt32BE(16), 1200); assert.equal(png.readUInt32BE(20), 630);
  return `${image.pathname} ${png.length} bytes`;
});

await check("registry contract is deployed on testnet", async () => {
  const account = await rpc("testnet", "query", { request_type: "view_account", account_id: REGISTRY, finality: "final" });
  assert.notEqual(account.code_hash, "11111111111111111111111111111111", "no contract code on the registry account");
  return `${REGISTRY} code_hash ${account.code_hash}`;
});

for (const item of EVIDENCE) {
  await check(`evidence tx: ${item.name}`, async () => {
    const tx = await rpc("testnet", "tx", { tx_hash: item.hash, sender_account_id: DEMO, wait_until: "FINAL" });
    assert.equal(tx.transaction.receiver_id, REGISTRY);
    assert.equal(tx.transaction.actions[0].FunctionCall.method_name, "verify");
    const verdict = JSON.parse(Buffer.from(tx.status.SuccessValue, "base64").toString("utf8"));
    assert.equal(verdict.ok, item.ok, `verify returned ok:${verdict.ok}`);
    return `${item.hash.slice(0, 8)}… ok:${verdict.ok} (${verdict.reason})`;
  });
}

await check("live run: signed challenge, enclave receipt, check(), a new verify() tx", async () => {
  const response = await fetch(`${LIVE}/api/demo`, { method: "POST", headers: { "content-type": "application/json", "x-wrench-visitor": crypto.randomUUID() }, body: JSON.stringify({ fresh: false }) });
  assert.equal(response.status, 200, `HTTP ${response.status}`);
  const events = await readStream(response);
  const stages = events.map(e => e.stage);
  const failure = events.find(e => e.stage === "error");
  assert.ok(!failure, `stream error: ${failure?.error}`);
  assert.deepEqual(stages.filter(s => ["sign", "owner", "collect", "enclave", "check", "tx", "dossier", "done"].includes(s)), ["sign", "owner", "collect", "enclave", "check", "tx", "dossier", "done"], `stages ${stages.join(",")}`);
  const tx = events.find(e => e.stage === "tx").tx;
  assert.equal(tx.verdict.ok, true);
  const chain = await rpc("testnet", "tx", { tx_hash: tx.tx_hash, sender_account_id: tx.signer_id, wait_until: "FINAL" });
  assert.equal(chain.transaction.receiver_id, REGISTRY);
  return `tx ${tx.tx_hash.slice(0, 8)}… final in ${(tx.elapsed_ms / 1000).toFixed(1)} s`;
});

await check("live refusal: a valid signature for an account the key does not control", async () => {
  const body = await (await fetch(`${LIVE}/api/demo-unowned`, { method: "POST", headers: { "content-type": "application/json", "x-wrench-visitor": crypto.randomUUID() }, body: JSON.stringify({ accountId: "near.testnet" }) })).json();
  assert.equal(body.refused, true);
  assert.equal(body.signature_cryptographically_valid, true);
  return body.reason;
});

await check("live tamper: one flipped bit is refused on chain", async () => {
  const body = await (await fetch(`${LIVE}/api/tamper`, { method: "POST", headers: { "content-type": "application/json", "x-wrench-visitor": crypto.randomUUID() }, body: "{}" })).json();
  assert.equal(body.tx?.verdict?.ok, false);
  assert.match(body.tx.verdict.reason, /does not verify/);
  return `tx ${body.tx.tx_hash.slice(0, 8)}… ok:false`;
});

const width = Math.max(...results.map(r => r.name.length));
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name.padEnd(width)}  ${r.detail}  (${(r.ms / 1000).toFixed(1)} s)`);
const failed = results.filter(r => !r.pass).length;
console.log(`\n${results.length - failed}/${results.length} checks passed against ${LIVE}`);
process.exit(failed ? 1 : 0);
