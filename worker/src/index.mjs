import { DurableObject } from "cloudflare:workers";
import { createHash, createPrivateKey, randomBytes, randomUUID, sign as signBytes } from "node:crypto";
import { collectPublicData, confidentialQuote, decodeBase58, nep413Bytes, recheckReceipt, requestAttestedDossier, verifyAccountOwnership, verifyLinkedAddress, verifyNep413 } from "../../scripts/wrench.mjs";

const CSP = "default-src 'self'; connect-src 'self' https://esm.sh https://rpc.mainnet.fastnear.com https://helper.mainnet.near.org https://app.mynearwallet.com https://api.mynearwallet.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://esm.sh; base-uri 'none'; frame-ancestors 'none'";
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const pad = n => String(n).padStart(15, "0");

export class WrenchState extends DurableObject {
  async limit(ipHash, paid, caps) {
    const now = Date.now();
    const day = Math.floor(now / 86_400_000), tenMin = Math.floor(now / 600_000), minute = Math.floor(now / 60_000);
    const windows = paid
      ? [[`ipd:${ipHash}:${day}`, caps.ipDay, (day + 1) * 86_400_000], [`ip10:${ipHash}:${tenMin}`, caps.ip10, (tenMin + 1) * 600_000], [`gd:${day}`, caps.globalDay, (day + 1) * 86_400_000]]
      : [[`ipm:${ipHash}:${minute}`, caps.cheapMin, (minute + 1) * 60_000]];
    const counts = await Promise.all(windows.map(([key]) => this.ctx.storage.get(`c:${key}`)));
    for (const [i, [key, cap, resetAt]] of windows.entries()) {
      if ((counts[i]?.n ?? 0) >= cap) return { ok: false, scope: key.startsWith("gd:") ? "global" : "ip", retryAfter: Math.ceil((resetAt - now) / 1000) };
    }
    await Promise.all(windows.map(([key, , resetAt], i) => this.ctx.storage.put(`c:${key}`, { n: (counts[i]?.n ?? 0) + 1, expires: resetAt })));
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(now + 3_600_000);
    return { ok: true, globalToday: (counts[windows.length - 1]?.n ?? 0) + 1 };
  }
  async alarm() {
    const now = Date.now();
    for (const prefix of ["c:", "challenge:", "session:"]) {
      const rows = await this.ctx.storage.list({ prefix });
      const dead = [...rows].filter(([, v]) => v.expires < now).map(([k]) => k);
      if (dead.length) await this.ctx.storage.delete(dead);
    }
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

function demoSigner(env) {
  if (!env.DEMO_SIGNER_KEY) throw new HttpError(503, "Demo signer is not configured.");
  const seed = decodeBase58(env.DEMO_SIGNER_KEY.trim().slice("ed25519:".length)).subarray(0, 32);
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
}

function signDemoProof(env, claimedAccount) {
  const nonce = randomBytes(32);
  const payload = { message: `Authorize Wrench dossier for ${claimedAccount} nonce=${nonce.toString("hex")}`, nonce: nonce.toString("base64"), recipient: "wrench.local" };
  const digest = createHash("sha256").update(nep413Bytes(payload)).digest();
  const signature = signBytes(null, digest, demoSigner(env)).toString("base64");
  const publicKey = env.DEMO_PUBLIC_KEY;
  return { accountId: claimedAccount, publicKey, signature, payload };
}

async function attestedReview({ proof, network, env, linked = [] }) {
  const t0 = Date.now();
  const owner = await verifyAccountOwnership(proof, network);
  const t1 = Date.now();
  const bundle = await collectPublicData(proof.accountId, network, linked);
  bundle.ownership = owner;
  const t2 = Date.now();
  const result = await requestAttestedDossier(bundle, env.NEAR_AI_API_KEY);
  const timings_ms = { ownership: t1 - t0, collect: t2 - t1, model_and_registry: Date.now() - t2 };
  const evidence = {
    timings_ms, network, collected_at: bundle.collected_at, balance_yocto: bundle.balances.near, recent_transactions: bundle.recent_transactions.length,
    top_counterparties: bundle.top_counterparties, sources: bundle.sources,
  };
  return { bundle, owner, evidence, ...result };
}

const REPLAY_MAX_AGE_MS = 3 * 3_600_000;
const humanAge = ms => ms < 90_000 ? "moments ago" : ms < 5_400_000 ? `${Math.round(ms / 60_000)} minutes ago` : `${Math.round(ms / 3_600_000)} hours ago`;

async function freshDemo(env, state) {
  const proof = signDemoProof(env, env.DEMO_ACCOUNT);
  const review = await attestedReview({ proof, network: "testnet", env });
  const out = { at: new Date().toISOString(), network: "testnet", demo_account: env.DEMO_ACCOUNT, ownership: review.owner, evidence: review.evidence, dossier: review.dossier, attestation: review.attestation };
  await state.saveLast(out);
  return out;
}

async function gate(env, request, paid) {
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const ipHash = createHash("sha256").update(`wrench:${ip}`).digest("hex").slice(0, 16);
  const caps = { ipDay: Number(env.PAID_PER_IP_DAY), ip10: Number(env.PAID_PER_IP_10MIN), globalDay: Number(env.PAID_GLOBAL_DAY), cheapMin: Number(env.CHEAP_PER_IP_MIN) };
  return env.STATE.getByName("wrench").limit(ipHash, paid, caps);
}

async function route(request, env) {
  const url = new URL(request.url);
  const state = env.STATE.getByName("wrench");
  const path = url.pathname;
  const method = request.method;

  if (method === "GET" && path === "/api/health") {
    return json(200, { ok: true, demo_account: env.DEMO_ACCOUNT, paid_calls_today: await state.usage(), paid_calls_daily_cap: Number(env.PAID_GLOBAL_DAY), per_ip_daily_cap: Number(env.PAID_PER_IP_DAY) });
  }

  if (method === "POST" && path === "/api/demo") {
    const input = await bodyJson(request);
    const last = await state.getLast();
    const ageMs = last ? Date.now() - Date.parse(last.at) : Infinity;
    const replay = async notice => json(200, { ...last, replayed: true, age_seconds: Math.round(ageMs / 1000), attestation: await recheckReceipt(last.attestation), notice });
    if (!input.fresh && ageMs < REPLAY_MAX_AGE_MS) {
      const cheap = await gate(env, request, false);
      if (!cheap.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: cheap.retryAfter });
      return replay(`Attested review from ${humanAge(ageMs)}. The registry check below ran just now.`);
    }
    const verdict = await gate(env, request, true);
    if (!verdict.ok) {
      if (!last) throw new HttpError(429, `Demo budget reached (${verdict.scope}). Try again in ${Math.ceil(verdict.retryAfter / 60)} minutes.`, { retryAfter: verdict.retryAfter });
      return replay(`Fresh model calls are limited per visitor and per day. Showing the attested review from ${humanAge(ageMs)}; the registry check below ran just now.`);
    }
    return json(200, await freshDemo(env, state));
  }

  if (method === "POST" && path === "/api/demo-unowned") {
    const verdict = await gate(env, request, false);
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
    const verdict = await gate(env, request, false);
    if (!verdict.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: verdict.retryAfter });
    const id = url.searchParams.get("accountId");
    if (!accountId(id)) throw new HttpError(400, "Enter a valid NEAR account ID.");
    const nonce = randomBytes(32), nonceHex = nonce.toString("hex");
    const payload = { message: `Authorize Wrench dossier for ${id} nonce=${nonceHex}`, nonce: nonce.toString("base64"), recipient: "wrench.local" };
    const challengeId = randomUUID();
    await state.putChallenge(challengeId, { id, nonceHex, payload, expires: Date.now() + 5 * 60_000 });
    return json(200, { challengeId, payload, linkMessages: { evm: `Authorize Wrench link evm <ADDRESS> for ${id} nonce=${nonceHex}`, solana: `Authorize Wrench link solana <ADDRESS> for ${id} nonce=${nonceHex}` } });
  }

  if (method === "POST" && path === "/api/dossier") {
    const verdict = await gate(env, request, true);
    if (!verdict.ok) throw new HttpError(429, `Review budget reached (${verdict.scope}). Try again in ${Math.ceil(verdict.retryAfter / 60)} minutes, or run the no-wallet demo.`, { retryAfter: verdict.retryAfter });
    const input = await bodyJson(request);
    const challenge = await state.takeChallenge(input.challengeId);
    if (!challenge) throw new HttpError(400, "Signing challenge expired or already used. Request a fresh one.");
    if (input.proof?.accountId !== challenge.id) throw new HttpError(400, "Signature account does not match the requested account.");
    const proof = { ...input.proof, payload: challenge.payload };
    const linked = [];
    for (const item of input.linkedAddresses ?? []) {
      linked.push(await verifyLinkedAddress(item, `Authorize Wrench link ${item.chain} ${item.address} for ${proof.accountId} nonce=${challenge.nonceHex}`));
    }
    const review = await attestedReview({ proof, network: "mainnet", env, linked });
    const session = randomUUID();
    await state.putSession(session, { proof, balance: review.bundle.balances.near, expires: Date.now() + 10 * 60_000 });
    return json(200, { dossier: review.dossier, attestation: review.attestation, ownership: review.owner, evidence: review.evidence, session });
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
    const verdict = await gate(env, request, false);
    if (!verdict.ok) throw new HttpError(429, "Too many requests. Wait a minute.", { retryAfter: verdict.retryAfter });
    const input = await bodyJson(request);
    const session = await state.getSession(input.session);
    if (!session) throw new HttpError(401, "Dossier session expired. Run a new signed review before requesting a quote.");
    if (!session.oneClickToken || session.oneClickTokenExpires < Date.now()) throw new HttpError(401, "Sign the NEAR Intents ownership request before quoting.");
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
    const caps = { ipDay: 1e9, ip10: 1e9, globalDay: Number(env.PAID_GLOBAL_DAY), cheapMin: 1e9 };
    if (!(await state.limit("cron", true, caps)).ok) return;
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
