import { DurableObject } from "cloudflare:workers";
import { createHash, createPrivateKey, randomBytes, randomUUID, sign as signBytes } from "node:crypto";
import { MODEL, collectPublicData, formatNear, confidentialQuote, decodeBase58, nep413Bytes, recheckReceipt, requestAttestedDossier, verifyAccountOwnership, verifyLinkedAddress, verifyNep413, verifyOnChain } from "../../scripts/wrench.mjs";

const CSP = "default-src 'self'; connect-src 'self' https:; frame-src https: blob: data:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://esm.sh; worker-src blob:; base-uri 'none'; frame-ancestors 'none'";
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const pad = n => String(n).padStart(15, "0");

export class WrenchState extends DurableObject {
  async limit(kind, ipHash, visitor, caps) {
    const now = Date.now();
    const day = Math.floor(now / 86_400_000), tenMin = Math.floor(now / 600_000), minute = Math.floor(now / 60_000);
    const dayEnd = (day + 1) * 86_400_000;
    const table = {
      cheap: { visitor: null, soft: [[`ipm:${ipHash}:${minute}`, caps.cheapMin, (minute + 1) * 60_000]], hard: [] },
      paid: { visitor: [`vp:${visitor}:${day}`, caps.visitorPaidDay, dayEnd], soft: [[`ipd:${ipHash}:${day}`, caps.ipDay, dayEnd], [`ip10:${ipHash}:${tenMin}`, caps.ip10, (tenMin + 1) * 600_000]], hard: [[`gd:${day}`, caps.globalDay, dayEnd]] },
      tx: { visitor: [`vt:${visitor}:${day}`, caps.visitorTxDay, dayEnd], soft: [[`ipt:${ipHash}:${day}`, caps.ipTxDay, dayEnd]], hard: [[`gt:${day}`, caps.globalTxDay, dayEnd]] },
    }[kind];
    const visitorCount = table.visitor ? ((await this.ctx.storage.get(`c:${table.visitor[0]}`))?.n ?? 0) : 1;
    const firstRun = table.visitor && visitorCount === 0;
    const windows = [...(table.visitor ? [[...table.visitor, "visitor"]] : []), ...(firstRun ? [] : table.soft.map(w => [...w, "ip"])), ...table.hard.map(w => [...w, "global"])];
    const counts = await Promise.all(windows.map(([key]) => this.ctx.storage.get(`c:${key}`)));
    for (const [i, [, cap, resetAt, scope]] of windows.entries()) {
      if ((counts[i]?.n ?? 0) >= cap) return { ok: false, scope, retryAfter: Math.ceil((resetAt - now) / 1000) };
    }
    await Promise.all(windows.map(([key, , resetAt], i) => this.ctx.storage.put(`c:${key}`, { n: (counts[i]?.n ?? 0) + 1, expires: resetAt })));
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(now + 3_600_000);
    return { ok: true, firstRun: Boolean(firstRun) };
  }
  async alarm() {
    const now = Date.now();
    for (const prefix of ["c:", "challenge:", "session:"]) {
      const rows = await this.ctx.storage.list({ prefix });
      const dead = [...rows].filter(([, v]) => v.expires < now).map(([k]) => k);
      if (dead.length) await this.ctx.storage.delete(dead);
    }
  }
  async allocNonce(signer, chainNonce) {
    const key = `nonce:${signer}`;
    const next = Math.max((await this.ctx.storage.get(key)) ?? 0, chainNonce) + 1;
    await this.ctx.storage.put(key, next);
    return next;
  }
  async putChallenge(id, value) { await this.ctx.storage.put(`challenge:${id}`, value); }
  async takeChallenge(id) {
    const value = await this.ctx.storage.get(`challenge:${id}`);
    if (!value) return null;
    await this.ctx.storage.delete(`challenge:${id}`);
    return value.expires < Date.now() ? null : value;
  }
  async putSession(id, value) { await this.ctx.storage.put(`session:${id}`, value); }
  async getSession(id) {
    const value = await this.ctx.storage.get(`session:${id}`);
    return value && value.expires >= Date.now() ? value : null;
  }
  async saveLast(result) { await this.ctx.storage.put("last-demo", result); }
  async getLast() { return (await this.ctx.storage.get("last-demo")) ?? null; }
  async usage() {
    const day = Math.floor(Date.now() / 86_400_000);
    return (await this.ctx.storage.get(`c:gd:${day}`))?.n ?? 0;
  }
}

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}

const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers } });
const accountId = value => typeof value === "string" && /^[a-z0-9._-]{2,64}$/.test(value);

async function bodyJson(request) {
  const text = await request.text();
  if (text.length > 128_000) throw new HttpError(413, "request body exceeds 128 KB");
  try { return JSON.parse(text || "{}"); } catch { throw new HttpError(400, "request body is not valid JSON"); }
}

function keyFrom(secret, label) {
  if (!secret) throw new HttpError(503, `${label} is not configured.`);
  const seed = decodeBase58(secret.trim().slice("ed25519:".length)).subarray(0, 32);
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
}
const demoSigner = env => keyFrom(env.DEMO_SIGNER_KEY, "Demo signer");

function signDemoProof(env, claimedAccount) {
  const nonce = randomBytes(32);
  const payload = { message: `Authorize Wrench dossier for ${claimedAccount} nonce=${nonce.toString("hex")}`, nonce: nonce.toString("base64"), recipient: "wrench.local" };
  const digest = createHash("sha256").update(nep413Bytes(payload)).digest();
  const signature = signBytes(null, digest, demoSigner(env)).toString("base64");
  const publicKey = env.DEMO_PUBLIC_KEY;
  return { accountId: claimedAccount, publicKey, signature, payload };
}

const noop = () => {};

async function runPipeline({ env, state, emit = noop, proof, network, linked = [], replay = null, saveLast = false }) {
  const t0 = Date.now();
  const proofView = { account_id: proof.accountId, public_key: proof.publicKey, message: proof.payload.message, recipient: proof.payload.recipient, nonce: proof.payload.nonce, signature: proof.signature };
  await emit({ stage: "sign", proof: proofView, at_ms: 0 });
  const owner = await verifyAccountOwnership(proof, network);
  await emit({ stage: "owner", ownership: owner, at_ms: Date.now() - t0 });
  let dossier, attestation, evidence, at, seen, balance = null;
  if (replay) {
    ({ dossier, evidence, at } = replay);
    seen = { account_id: replay.demo_account, balance: `${formatNear(evidence.balance_yocto)} NEAR`, transactions: evidence.recent_transactions, counterparties: evidence.top_counterparties, ...replay.enclave_sees, sources: evidence.sources };
    await emit({ stage: "collect", replayed: true, enclave_sees: seen, at_ms: Date.now() - t0 });
    await emit({ stage: "enclave", replayed: true, model: replay.attestation.model, registry: replay.attestation.registry, registered_key: replay.attestation.registered_key, request_sha256: replay.attestation.request_sha256, response_sha256: replay.attestation.response_sha256, signature: replay.attestation.signature, at, at_ms: Date.now() - t0 });
    attestation = await recheckReceipt(replay.attestation);
    await emit({ stage: "check", verdict: attestation.verdict, block: attestation.verdict_block, at_ms: Date.now() - t0 });
  } else {
    const bundle = await collectPublicData(proof.accountId, network, linked);
    bundle.ownership = owner;
    balance = bundle.balances.near;
    seen = enclaveSees(bundle);
    await emit({ stage: "collect", enclave_sees: seen, at_ms: Date.now() - t0 });
    const result = await requestAttestedDossier(bundle, env.NEAR_AI_API_KEY, MODEL, async event => emit({ ...event, at_ms: Date.now() - t0 }));
    dossier = result.dossier; attestation = result.attestation; at = new Date().toISOString();
    evidence = { network, collected_at: bundle.collected_at, balance_yocto: bundle.balances.near, recent_transactions: bundle.recent_transactions.length, top_counterparties: bundle.top_counterparties, sources: bundle.sources };
  }
  const record = { at, network, demo_account: proof.accountId, ownership: owner, evidence, enclave_sees: seen, proof: proofView, dossier, attestation };
  if (saveLast && !replay) await state.saveLast(record);
  const tx = await verifyOnChain({ attestation, ...demoKey(env) });
  await emit({ stage: "tx", tx, at_ms: Date.now() - t0 });
  if (saveLast && !replay) await state.saveLast({ ...record, tx });
  await emit({ stage: "dossier", dossier, evidence, attestation: { ...attestation, signature: undefined }, at, at_ms: Date.now() - t0 });
  return { owner, balance, total_ms: Date.now() - t0, fresh: !replay };
}

const REPLAY_MAX_AGE_MS = 3 * 3_600_000;
const humanAge = ms => ms < 90_000 ? "moments ago" : ms < 5_400_000 ? `${Math.round(ms / 60_000)} minutes ago` : `${Math.round(ms / 3_600_000)} hours ago`;

async function freshDemo(env, state) {
  const proof = signDemoProof(env, env.DEMO_ACCOUNT);
  return runPipeline({ env, state, proof, network: "testnet", saveLast: true });
}

async function gate(env, request, kind) {
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const ipHash = createHash("sha256").update(`wrench:${ip}`).digest("hex").slice(0, 16);
  const token = request.headers.get("x-wrench-visitor") ?? "";
  const visitor = /^[0-9a-f-]{16,64}$/.test(token) ? token : `ip-${ipHash}`;
  const caps = {
    ipDay: Number(env.PAID_PER_IP_DAY), ip10: Number(env.PAID_PER_IP_10MIN), globalDay: Number(env.PAID_GLOBAL_DAY), cheapMin: Number(env.CHEAP_PER_IP_MIN),
    visitorPaidDay: Number(env.PAID_PER_VISITOR_DAY), visitorTxDay: Number(env.TX_PER_VISITOR_DAY), ipTxDay: Number(env.TX_PER_IP_DAY), globalTxDay: Number(env.TX_GLOBAL_DAY),
  };
  return env.STATE.getByName("wrench").limit(kind, ipHash, visitor, caps);
}

const friendly = message => /HTTP 429|Rate limit/i.test(message) ? "NEAR testnet RPC is rate limiting right now. Retry in a few seconds." : /HTTP 5\d\d|timed out|timeout|fetch failed|aborted/i.test(message) ? "A NEAR testnet RPC node did not answer in time. Retry in a few seconds." : message.length > 400 ? `${message.slice(0, 400)}...` : message;

function ndjson(run) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter(), encoder = new TextEncoder();
  const emit = value => writer.write(encoder.encode(`${JSON.stringify(value)}\n`));
  (async () => {
    try { await run(emit); } catch (error) { await emit({ stage: "error", status: error.status ?? 502, error: friendly(error.message) }).catch(() => {}); }
    finally { await writer.close().catch(() => {}); }
  })();
  return new Response(readable, { headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

const enclaveSees = bundle => ({
  account_id: bundle.account_id, balance: bundle.balances.near_formatted, staked: bundle.balances.staked_near_formatted,
  access_keys: { full_access: bundle.access_keys.filter(k => k.permission === "FullAccess").length, function_call: bundle.access_keys.filter(k => k.permission !== "FullAccess").length },
  token_holdings: bundle.ft_holdings.length, staking_pools: bundle.staking.length, transactions: bundle.recent_transactions.length,
  counterparties: bundle.top_counterparties, subaccounts_created: bundle.named_subaccounts_created.length,
  social_profile: Boolean(bundle.near_social_profile && Object.keys(bundle.near_social_profile).length), sources: bundle.sources,
});

function demoKey(env) {
  return { allocateNonce: chainNonce => env.STATE.getByName("wrench").allocNonce(env.OP_ACCOUNT, chainNonce), signerId: env.OP_ACCOUNT, publicKey: env.OP_PUBLIC_KEY, privateKey: keyFrom(env.OP_SIGNER_KEY, "Operator signer") };
}

async function route(request, env) {
  const url = new URL(request.url);
  const state = env.STATE.getByName("wrench");
  const path = url.pathname;
  const method = request.method;

  if (method === "GET" && path === "/api/health") {
    return json(200, { ok: true, demo_account: env.DEMO_ACCOUNT, paid_calls_today: await state.usage(), paid_calls_daily_cap: Number(env.PAID_GLOBAL_DAY), per_ip_daily_cap: Number(env.PAID_PER_IP_DAY) });
  }

  if (method === "GET" && path === "/api/last") {
    const last = await state.getLast();
    if (!last?.tx) return json(200, { last: null });
    return json(200, { last: { at: last.at, demo_account: last.demo_account, ownership: last.ownership, enclave_sees: last.enclave_sees ?? null, proof: last.proof ?? null, attestation: { model: last.attestation.model, registry: last.attestation.registry, registered_key: last.attestation.registered_key, request_sha256: last.attestation.request_sha256, response_sha256: last.attestation.response_sha256, signature: last.attestation.signature, verdict: last.attestation.verdict, verdict_block: last.attestation.verdict_block }, tx: last.tx } });
  }

  if (method === "POST" && path === "/api/demo") {
    const input = await bodyJson(request);
    const last = await state.getLast();
    let fresh = false, notice = "";
    const replayOnly = input.fresh === false && last;
    const paid = replayOnly ? { ok: false } : await gate(env, request, "paid");
    if (replayOnly) {
      const cheap = await gate(env, request, "cheap");
      if (!cheap.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: cheap.retryAfter });
    } else if (paid.ok) fresh = true;
    else if (!last) throw new HttpError(429, `Demo budget reached (${paid.scope}). Try again in ${Math.ceil(paid.retryAfter / 60)} minutes.`, { retryAfter: paid.retryAfter });
    else notice = `Fresh model calls are limited per visitor and per day. This run re-verifies the attested review from ${humanAge(Date.now() - Date.parse(last.at))} on chain.`;
    const txGate = await gate(env, request, "tx");
    if (!txGate.ok) throw new HttpError(429, `On-chain verification budget reached (${txGate.scope}). Try again in ${Math.ceil(txGate.retryAfter / 60)} minutes.`, { retryAfter: txGate.retryAfter });
    const proof = signDemoProof(env, env.DEMO_ACCOUNT);
    return ndjson(async emit => {
      const out = await runPipeline({ env, state, emit, proof, network: "testnet", replay: fresh ? null : last, saveLast: true });
      await emit({ stage: "done", fresh, notice, total_ms: out.total_ms });
    });
  }

  if (method === "POST" && path === "/api/tamper") {
    const last = await state.getLast();
    if (!last) throw new HttpError(409, "No attested review exists yet. Run the review first.");
    const txGate = await gate(env, request, "tx");
    if (!txGate.ok) throw new HttpError(429, `On-chain verification budget reached (${txGate.scope}). Try again in ${Math.ceil(txGate.retryAfter / 60)} minutes.`, { retryAfter: txGate.retryAfter });
    const original = last.attestation.response_sha256;
    const flipped = (original[0] === "0" ? "1" : "0") + original.slice(1);
    const tx = await verifyOnChain({ attestation: { ...last.attestation, response_sha256: flipped }, ...demoKey(env) });
    return json(200, { tx, tampered: { field: "response_sha256", original, submitted: flipped } });
  }

  if (method === "POST" && path === "/api/demo-unowned") {
    const verdict = await gate(env, request, "cheap");
    if (!verdict.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: verdict.retryAfter });
    const input = await bodyJson(request);
    const target = String(input.accountId ?? "").trim();
    if (!accountId(target)) throw new HttpError(400, "Enter a valid NEAR account ID.");
    if (target === env.DEMO_ACCOUNT) throw new HttpError(400, "That is the demo account the signer owns. Enter any other account.");
    const proof = signDemoProof(env, target);
    const cryptoValid = verifyNep413(proof);
    try {
      await verifyAccountOwnership(proof, "testnet");
    } catch (error) {
      if (!/FullAccess|signature refused|does not authorize/.test(error.message)) throw error;
      return json(200, { refused: true, target, signature_cryptographically_valid: cryptoValid, signer_public_key: proof.publicKey, reason: error.message, checked: "NEAR testnet RPC view_access_key for the signer key on the claimed account" });
    }
    throw new HttpError(500, `Unexpected: ${target} accepted the demo key. Wrench did not collect data, but the check should have refused.`);
  }

  if (method === "GET" && path === "/api/challenge") {
    const verdict = await gate(env, request, "cheap");
    if (!verdict.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: verdict.retryAfter });
    const id = url.searchParams.get("accountId");
    const network = url.searchParams.get("network") === "mainnet" ? "mainnet" : "testnet";
    if (!accountId(id)) throw new HttpError(400, "Enter a valid NEAR account ID.");
    const nonce = randomBytes(32), nonceHex = nonce.toString("hex");
    const payload = { message: `Authorize Wrench dossier for ${id} nonce=${nonceHex}`, nonce: nonce.toString("base64"), recipient: "wrench.local" };
    const challengeId = randomUUID();
    await state.putChallenge(challengeId, { id, nonceHex, payload, network, expires: Date.now() + 5 * 60_000 });
    return json(200, { challengeId, network, payload, linkMessages: { evm: `Authorize Wrench link evm <ADDRESS> for ${id} nonce=${nonceHex}`, solana: `Authorize Wrench link solana <ADDRESS> for ${id} nonce=${nonceHex}` } });
  }

  if (method === "POST" && path === "/api/dossier") {
    const verdict = await gate(env, request, "paid");
    if (!verdict.ok) throw new HttpError(429, `Review budget reached (${verdict.scope}). Try again in ${Math.ceil(verdict.retryAfter / 60)} minutes, or run the no-wallet demo.`, { retryAfter: verdict.retryAfter });
    const txGate = await gate(env, request, "tx");
    if (!txGate.ok) throw new HttpError(429, `On-chain verification budget reached (${txGate.scope}). Try again in ${Math.ceil(txGate.retryAfter / 60)} minutes.`, { retryAfter: txGate.retryAfter });
    const input = await bodyJson(request);
    const challenge = await state.takeChallenge(input.challengeId);
    if (!challenge) throw new HttpError(400, "Signing challenge expired or already used. Request a fresh one.");
    if (input.proof?.accountId !== challenge.id) throw new HttpError(400, "Signature account does not match the requested account.");
    const proof = { ...input.proof, payload: challenge.payload };
    const linked = [];
    for (const item of input.linkedAddresses ?? []) {
      linked.push(await verifyLinkedAddress(item, `Authorize Wrench link ${item.chain} ${item.address} for ${proof.accountId} nonce=${challenge.nonceHex}`));
    }
    return ndjson(async emit => {
      const out = await runPipeline({ env, state, emit, proof, network: challenge.network ?? "testnet", linked });
      const session = randomUUID();
      await state.putSession(session, { proof, balance: out.balance, network: challenge.network ?? "testnet", expires: Date.now() + 10 * 60_000 });
      await emit({ stage: "done", fresh: true, session, network: challenge.network ?? "testnet", total_ms: out.total_ms });
    });
  }

  if (method === "POST" && path === "/api/quote-session") {
    const input = await bodyJson(request);
    const session = await state.getSession(input.session);
    if (!session) throw new HttpError(401, "Dossier session expired. Run a new signed review before requesting a quote.");
    const signedData = input.signedData;
    if (signedData?.standard !== "nep413" || signedData.public_key !== session.proof.publicKey || signedData.payload?.recipient !== "intents.near" || !signedData.signature?.startsWith("ed25519:")) throw new HttpError(400, "The NEAR Intents signature must use the verified account key and intents.near recipient.");
    let intent;
    try { intent = JSON.parse(signedData.payload.message); } catch { throw new HttpError(400, "The NEAR Intents signature must contain a valid empty intent."); }
    const deadline = Date.parse(intent.deadline);
    if (intent.signer_id !== session.proof.accountId || !Array.isArray(intent.intents) || intent.intents.length !== 0 || !Number.isFinite(deadline) || deadline <= Date.now() || deadline > Date.now() + 5 * 60_000) throw new HttpError(400, "The NEAR Intents signature must authorize only an empty intent for this account and expire within five minutes.");
    let signature;
    try { signature = decodeBase58(signedData.signature.slice("ed25519:".length)); } catch { throw new HttpError(400, "The NEAR Intents signature encoding is invalid."); }
    if (signature.length !== 64 || !verifyNep413({ accountId: session.proof.accountId, publicKey: signedData.public_key, signature: signature.toString("base64"), payload: signedData.payload })) throw new HttpError(400, "The NEAR Intents signature did not verify.");
    const response = await fetch("https://1click.chaindefuser.com/v0/auth/authenticate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signedData }), signal: AbortSignal.timeout(15000) });
    const auth = await response.json();
    if (!response.ok) throw new HttpError(response.status, auth.message ?? auth.error ?? "1Click user authentication failed.");
    if (typeof auth.accessToken !== "string" || !Number.isFinite(auth.expiresIn)) throw new HttpError(502, "1Click returned an invalid user session.");
    await state.putSession(input.session, { ...session, oneClickToken: auth.accessToken, oneClickTokenExpires: Date.now() + auth.expiresIn * 1000 });
    return json(200, { expiresIn: auth.expiresIn });
  }

  if (method === "POST" && path === "/api/quote") {
    const verdict = await gate(env, request, "cheap");
    if (!verdict.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: verdict.retryAfter });
    const input = await bodyJson(request);
    const session = await state.getSession(input.session);
    if (!session) throw new HttpError(401, "Dossier session expired. Run a new signed review before requesting a quote.");
    if (!session.oneClickToken || session.oneClickTokenExpires < Date.now()) throw new HttpError(401, "Sign the NEAR Intents ownership request before quoting.");
    if (session.network !== "mainnet") throw new HttpError(400, "Confidential 1Click quotes use a mainnet account. Connect a mainnet wallet and review it first.");
    const owner = await verifyAccountOwnership(session.proof, "mainnet");
    const amount = String(input.amount ?? "");
    if (!/^\d+$/.test(amount) || BigInt(amount) > BigInt(session.balance)) throw new HttpError(400, "Amount must be a positive integer no greater than the verified public NEAR balance.");
    if (BigInt(amount) === 0n) throw new HttpError(400, "Amount must be greater than zero.");
    const quote = await confidentialQuote({ recipient: owner.account_id, refundTo: owner.account_id, originAsset: "nep141:wrap.near", destinationAsset: "nep141:wrap.near", amount, accessToken: session.oneClickToken });
    return json(200, quote);
  }

  return json(404, { error: "Route not found" });
}

export default {
  async scheduled(controller, env) {
    const state = env.STATE.getByName("wrench");
    const caps = { ipDay: 1e9, ip10: 1e9, globalDay: Number(env.PAID_GLOBAL_DAY), cheapMin: 1e9, visitorPaidDay: 1e9 };
    if (!(await state.limit("paid", "cron", "cron", caps)).ok) return;
    await freshDemo(env, state);
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/favicon.ico") return new Response(null, { status: 204, headers: { "cache-control": "public, max-age=86400" } });
    if (!url.pathname.startsWith("/api/")) {
      const asset = await env.ASSETS.fetch(request);
      const headers = new Headers(asset.headers);
      headers.set("x-content-type-options", "nosniff");
      if ((headers.get("content-type") ?? "").startsWith("text/html")) {
        headers.set("content-security-policy", CSP);
        headers.set("cache-control", "no-store");
      }
      return new Response(asset.body, { status: asset.status, headers });
    }
    try {
      return await route(request, env);
    } catch (error) {
      if (error instanceof HttpError) return json(error.status, { error: error.message }, error.extra.retryAfter ? { "retry-after": String(error.extra.retryAfter) } : {});
      return json(502, { error: error.message });
    }
  },
};
