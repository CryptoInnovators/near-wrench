import { createServer } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { collectPublicData, confidentialQuote, decodeBase58, requestAttestedDossier, verifyAccountOwnership, verifyLinkedAddress, verifyNep413 } from "./wrench.mjs";

const host = "127.0.0.1";
const port = Number(process.env.PORT ?? 8787);
const challenges = new Map();
const sessions = new Map();
const key = process.env.NEAR_AI_API_KEY;

function send(res, status, body, type = "application/json; charset=utf-8") {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; connect-src 'self' https://rpc.mainnet.fastnear.com https://helper.mainnet.near.org https://app.mynearwallet.com https://api.mynearwallet.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://esm.sh; base-uri 'none'; frame-ancestors 'none'" });
  res.end(type.startsWith("application/json") ? JSON.stringify(body) : body);
}

async function bodyJson(req) {
  let data = "";
  for await (const chunk of req) {
    data += chunk;
    if (data.length > 128_000) throw new Error("request body exceeds 128 KB");
  }
  return JSON.parse(data || "{}");
}

function accountId(value) {
  return typeof value === "string" && /^[a-z0-9._-]{2,64}$/.test(value);
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${host}:${port}`);
  if (req.method === "GET" && url.pathname === "/") {
    send(res, 200, await readFile(new URL("../web/index.html", import.meta.url), "utf8"), "text/html; charset=utf-8");
    return;
  }
  if (req.method === "GET" && url.pathname === "/favicon.ico") {
    res.writeHead(204, { "cache-control": "public, max-age=86400" }).end();
    return;
  }
  if (req.method === "GET" && url.pathname === "/api/challenge") {
    const id = url.searchParams.get("accountId");
    if (!accountId(id)) return send(res, 400, { error: "Enter a valid NEAR account ID." });
    const nonce = randomBytes(32);
    const nonceHex = nonce.toString("hex");
    const payload = { message: `Authorize Wrench dossier for ${id} nonce=${nonceHex}`, nonce: nonce.toString("base64"), recipient: "wrench.local" };
    const challengeId = randomUUID();
    challenges.set(challengeId, { id, nonceHex, payload, expires: Date.now() + 5 * 60_000, used: false });
    return send(res, 200, { challengeId, payload, linkMessages: { evm: `Authorize Wrench link evm <ADDRESS> for ${id} nonce=${nonceHex}`, solana: `Authorize Wrench link solana <ADDRESS> for ${id} nonce=${nonceHex}` } });
  }
  if (req.method === "POST" && url.pathname === "/api/dossier") {
    if (!key) return send(res, 503, { error: "NEAR_AI_API_KEY missing" });
    const input = await bodyJson(req);
    const challenge = challenges.get(input.challengeId);
    if (!challenge || challenge.used || challenge.expires < Date.now()) return send(res, 400, { error: "Signing challenge expired or already used. Request a fresh one." });
    if (input.proof?.accountId !== challenge.id) return send(res, 400, { error: "Signature account does not match the requested account." });
    const proof = { ...input.proof, payload: challenge.payload };
    challenge.used = true;
    const owner = await verifyAccountOwnership(proof, "mainnet");
    const linked = [];
    for (const item of input.linkedAddresses ?? []) {
      const expected = `Authorize Wrench link ${item.chain} ${item.address} for ${proof.accountId} nonce=${challenge.nonceHex}`;
      linked.push(await verifyLinkedAddress(item, expected));
    }
    const bundle = await collectPublicData(proof.accountId, "mainnet", linked);
    bundle.ownership = owner;
    const result = await requestAttestedDossier(bundle, key);
    const session = randomUUID();
    sessions.set(session, { proof, bundle, expires: Date.now() + 10 * 60_000 });
    return send(res, 200, { ...result, session });
  }
  if (req.method === "POST" && url.pathname === "/api/quote") {
    const input = await bodyJson(req);
    const session = sessions.get(input.session);
    if (!session || session.expires < Date.now()) return send(res, 401, { error: "Dossier session expired. Run a new signed review before requesting a quote." });
    if (!session.oneClickToken || session.oneClickTokenExpires < Date.now()) return send(res, 401, { error: "Sign the NEAR Intents ownership request before quoting." });
    const owner = await verifyAccountOwnership(session.proof, "mainnet");
    const amount = String(input.amount ?? "");
    if (!/^\d+$/.test(amount) || BigInt(amount) > BigInt(session.bundle.balances.near)) return send(res, 400, { error: "Amount must be a positive integer no greater than the verified public NEAR balance." });
    if (BigInt(amount) === 0n) return send(res, 400, { error: "Amount must be greater than zero." });
    const quote = await confidentialQuote({ recipient: owner.account_id, refundTo: owner.account_id, originAsset: "nep141:wrap.near", destinationAsset: "nep141:wrap.near", amount, accessToken: session.oneClickToken });
    return send(res, 200, quote);
  }
  if (req.method === "POST" && url.pathname === "/api/quote-session") {
    const input = await bodyJson(req);
    const session = sessions.get(input.session);
    if (!session || session.expires < Date.now()) return send(res, 401, { error: "Dossier session expired. Run a new signed review before requesting a quote." });
    const signedData = input.signedData;
    if (signedData?.standard !== "nep413" || signedData.public_key !== session.proof.publicKey || signedData.payload?.recipient !== "intents.near" || !signedData.signature?.startsWith("ed25519:")) return send(res, 400, { error: "The NEAR Intents signature must use the verified account key and intents.near recipient." });
    let intent;
    try { intent = JSON.parse(signedData.payload.message); } catch { return send(res, 400, { error: "The NEAR Intents signature must contain a valid empty intent." }); }
    const deadline = Date.parse(intent.deadline);
    if (intent.signer_id !== session.proof.accountId || !Array.isArray(intent.intents) || intent.intents.length !== 0 || !Number.isFinite(deadline) || deadline <= Date.now() || deadline > Date.now() + 5 * 60_000) return send(res, 400, { error: "The NEAR Intents signature must authorize only an empty intent for this account and expire within five minutes." });
    let signature;
    try { signature = decodeBase58(signedData.signature.slice("ed25519:".length)); } catch { return send(res, 400, { error: "The NEAR Intents signature encoding is invalid." }); }
    if (signature.length !== 64 || !verifyNep413({ accountId: session.proof.accountId, publicKey: signedData.public_key, signature: signature.toString("base64"), payload: signedData.payload })) return send(res, 400, { error: "The NEAR Intents signature did not verify." });
    const response = await fetch("https://1click.chaindefuser.com/v0/auth/authenticate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signedData }), signal: AbortSignal.timeout(15000) });
    const auth = await response.json();
    if (!response.ok) return send(res, response.status, { error: auth.message ?? auth.error ?? "1Click user authentication failed." });
    if (typeof auth.accessToken !== "string" || !Number.isFinite(auth.expiresIn)) return send(res, 502, { error: "1Click returned an invalid user session." });
    session.oneClickToken = auth.accessToken;
    session.oneClickTokenExpires = Date.now() + auth.expiresIn * 1000;
    return send(res, 200, { expiresIn: auth.expiresIn });
  }
  send(res, 404, { error: "Route not found" });
}

createServer((req, res) => {
  handle(req, res).catch(error => send(res, 502, { error: error.message }));
}).listen(port, host, () => console.log(`Wrench listening at http://${host}:${port}`));
