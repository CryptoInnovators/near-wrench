import { createHash, createPublicKey, randomUUID, sign as signBytes, verify as verifySignature } from "node:crypto";

export const MODEL = "Qwen/Qwen3.8-27B";
export const REGISTRY = "sworn-reg7-1113.testnet";
const NEP413_TAG = Buffer.from([0x9d, 0x01, 0x00, 0x80]);
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function decodeBase58(value) {
  let n = 0n;
  for (const c of value) {
    const digit = B58.indexOf(c);
    if (digit < 0) throw new Error("invalid base58 value");
    n = n * 58n + BigInt(digit);
  }
  const hex = n.toString(16);
  const tail = n ? Buffer.from(hex.padStart(Math.ceil(hex.length / 2) * 2, "0"), "hex") : Buffer.alloc(0);
  let zeroes = 0;
  while (value[zeroes] === "1") zeroes += 1;
  return Buffer.concat([Buffer.alloc(zeroes), tail]);
}

const borshString = value => {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32LE(bytes.length);
  return Buffer.concat([length, bytes]);
};

export function nep413Bytes(payload) {
  const nonce = Buffer.from(payload.nonce, "base64");
  if (nonce.length !== 32) throw new Error("NEP-413 nonce must be 32 bytes");
  return Buffer.concat([
    NEP413_TAG,
    borshString(payload.message),
    nonce,
    borshString(payload.recipient),
    payload.callbackUrl == null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), borshString(payload.callbackUrl)]),
  ]);
}

export function verifyNep413(proof) {
  if (!/^[a-z0-9._-]{2,64}$/.test(proof.accountId) || !proof.publicKey?.startsWith("ed25519:")) return false;
  try {
    const pub = decodeBase58(proof.publicKey.slice(8));
    const sig = Buffer.from(proof.signature, "base64");
    if (pub.length !== 32 || sig.length !== 64) return false;
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]), format: "der", type: "spki" });
    const digest = createHash("sha256").update(nep413Bytes(proof.payload)).digest();
    return verifySignature(null, digest, key, sig);
  } catch {
    return false;
  }
}

export function proofBindsAccount(proof) {
  const match = /^Authorize Wrench dossier for ([a-z0-9._-]{2,64}) nonce=([a-f0-9]{64})$/.exec(proof.payload?.message ?? "");
  if (!match || match[1] !== proof.accountId) return false;
  return Buffer.from(proof.payload.nonce, "base64").toString("hex") === match[2];
}

const RPC_URLS = { testnet: ["https://near-testnet.drpc.org", "https://archival-rpc.testnet.near.org", "https://test.rpc.fastnear.com"], mainnet: ["https://rpc.mainnet.fastnear.com"] };

export async function rpc(network, method, params) {
  const urls = RPC_URLS[network];
  let body;
  for (const [index, url] of urls.entries()) {
    try {
      body = await jsonFetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "wrench", method, params }) });
      break;
    } catch (error) {
      if (index === urls.length - 1) throw error;
    }
  }
  if (body.error) throw new Error(`NEAR RPC ${body.error.message}: ${body.error.data ?? ""}`);
  return body.result;
}

export async function verifyAccountOwnership(proof, network = "mainnet") {
  if (!verifyNep413(proof)) throw new Error("NEP-413 signature refused");
  if (!proofBindsAccount(proof)) throw new Error("NEP-413 message does not authorize this account and nonce");
  const access = await rpc(network, "query", { request_type: "view_access_key", finality: "final", account_id: proof.accountId, public_key: proof.publicKey });
  if (access.permission !== "FullAccess") throw new Error("NEP-413 key is not a FullAccess key for this account");
  return { account_id: proof.accountId, public_key: proof.publicKey, permission: access.permission, block_height: access.block_height, network };
}

export async function verifyLinkedAddress(link, expectedMessage) {
  if (link.message !== expectedMessage) throw new Error(`${link.chain} signature challenge refused`);
  if (link.chain === "evm") {
    if (!/^0x[0-9a-fA-F]{40}$/.test(link.address)) throw new Error("invalid EVM address");
    const { spawnSync } = await import("node:child_process");
    const checked = spawnSync("cast", ["wallet", "verify", "--quiet", "--address", link.address, expectedMessage, link.signature], { encoding: "utf8" });
    if (checked.status !== 0) throw new Error("EVM signature refused");
    const resolved = await jsonFetch(`https://api.ensideas.com/ens/resolve/${link.address}`);
    return { chain: "evm", address: link.address, ens: resolved.name || null, source: `https://api.ensideas.com/ens/resolve/${link.address}` };
  }
  if (link.chain === "solana") {
    const publicKey = decodeBase58(link.address);
    const signature = Buffer.from(link.signature, "base64");
    if (publicKey.length !== 32 || signature.length !== 64) throw new Error("invalid Solana key or signature encoding");
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]), format: "der", type: "spki" });
    if (!verifySignature(null, Buffer.from(expectedMessage), key, signature)) throw new Error("Solana signature refused");
    const result = await jsonFetch(`https://sdk-proxy-v2.sns.id/primary-domain/${encodeURIComponent(link.address)}`);
    return { chain: "solana", address: link.address, sns: result.result?.domain ?? null, source: `https://sdk-proxy-v2.sns.id/primary-domain/${link.address}` };
  }
  throw new Error(`unsupported linked chain: ${link.chain}`);
}

async function jsonFetch(url, options = {}) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const response = await fetch(url, { ...options, signal: options.signal ?? AbortSignal.timeout(15000) });
    if ((response.status === 429 || response.status >= 500) && attempt < 2) {
      const retryAfter = Number(response.headers.get("retry-after"));
      await new Promise(resolve => setTimeout(resolve, Math.min(retryAfter ? retryAfter * 1000 : 500 * 2 ** attempt, 5000)));
      continue;
    }
    const body = await response.json();
    if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}: ${JSON.stringify(body).slice(0, 300)}`);
    if (body.errors?.length) throw new Error(`${url} error: ${body.errors.map(e => e.message).join("; ")}`);
    return body;
  }
  throw new Error(`${url} failed after retries`);
}

export function formatNear(yocto) {
  const value = BigInt(yocto);
  const whole = value / 10n ** 24n;
  const fraction = (value % 10n ** 24n).toString().padStart(24, "0").slice(0, 4).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : String(whole);
}

export async function collectPublicData(accountId, network = "mainnet", links = []) {
  const fastnear = network === "testnet" ? "https://test.api.fastnear.com" : "https://api.fastnear.com";
  const transactions = network === "testnet" ? "https://tx.test.fastnear.com/v0" : "https://tx.main.fastnear.com/v0";
  const [account, history, rpcAccount, social] = await Promise.all([
    jsonFetch(`${fastnear}/v1/account/${encodeURIComponent(accountId)}/full`),
    jsonFetch(`${transactions}/account`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ account_id: accountId, desc: true, limit: 20 }) }),
    rpc(network, "query", { request_type: "view_account", finality: "final", account_id: accountId }),
    jsonFetch(`https://api2.near.social/v1/accounts/${encodeURIComponent(accountId)}`),
  ]);
  const hashes = (history.account_txs ?? []).map(row => row.transaction_hash).filter(Boolean);
  const txResult = hashes.length ? await jsonFetch(`${transactions}/transactions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tx_hashes: hashes }) }) : { transactions: [] };
  const transactionRows = (txResult.transactions ?? []).map(row => row.transaction ?? row);
  const counterparties = new Map();
  const subaccounts = new Set();
  for (const tx of transactionRows) {
    const signer = tx.signer_id;
    const receiver = tx.receiver_id;
    const other = signer === accountId ? receiver : signer;
    if (other && other !== accountId) counterparties.set(other, (counterparties.get(other) ?? 0) + 1);
    if (receiver?.endsWith(`.${accountId}`) && (tx.actions ?? []).some(a => a === "CreateAccount" || a.CreateAccount !== undefined)) subaccounts.add(receiver);
  }
  return {
    collected_at: new Date().toISOString(),
    network,
    account_id: accountId,
    account_ownership: "NEP-413 FullAccess verified before collection",
    balances: { near: rpcAccount.amount, staked_near: rpcAccount.locked, indexed: account.state?.balance, near_formatted: `${formatNear(rpcAccount.amount)} NEAR`, staked_near_formatted: `${formatNear(rpcAccount.locked)} NEAR`, unit: "raw fields are yoctoNEAR, 1 NEAR = 1e24; read the _formatted fields for amounts" },
    staking: account.pools ?? [],
    ft_holdings: account.tokens ?? [],
    mt_ft_holdings: [],
    ft_transfers: [],
    recent_transactions: transactionRows,
    top_counterparties: [...counterparties].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([account_id, transactions]) => ({ account_id, transactions })),
    named_subaccounts_created: [...subaccounts],
    near_intents_activity: [],
    near_social_profile: social,
    linked_addresses: links,
    data_quality: { recent_transactions: transactionRows.length, intents_history: "not indexed by the configured public source", mt_ft_holdings: "not included by FastNear full-account endpoint", ft_transfers: "not included by FastNear full-account endpoint" },
    sources: {
      near_rpc: network === "testnet" ? "https://near-testnet.drpc.org" : "https://rpc.mainnet.fastnear.com",
      fastnear_account: `${fastnear}/v1/account/${encodeURIComponent(accountId)}/full`,
      fastnear_transactions: `${transactions}/account`,
      near_social: `https://api2.near.social/v1/accounts/${encodeURIComponent(accountId)}`,
    },
  };
}

export function dossierPrompt(bundle) {
  return `You are conducting a defensive exposure review for the verified owner of this account. Use only evidence in the JSON. Treat account-to-person and location links as hypotheses, state uncertainty, and never invent a real-world identity, street address, home, or attack instructions. Estimate net worth only as a broad range from visible balances and mark missing prices. Return one JSON object with keys: summary, estimated_net_worth (range, currency, confidence, basis), linked_identities (array with identity, evidence_ids, confidence), likely_location_signals (array with signal, evidence_ids, confidence, caveat), three_links_that_leak_most (exactly three items, each with link, evidence_ids, why_it_matters, safe_action), and uncertainty. Every evidence_ids value must point to a source path in the supplied JSON. Do not give instructions for stalking, coercion, entry, physical attack, or account compromise. If evidence is insufficient, say so in the JSON.\n\n${JSON.stringify(bundle)}`;
}

export async function requestAttestedDossier(bundle, apiKey, model = MODEL, onStage = () => {}) {
  if (!apiKey) throw new Error("NEAR_AI_API_KEY missing");
  const registration = await view(REGISTRY, "get_latest", { model_id: model });
  if (!registration) throw new Error(`Sworn registration not found for model ${model}`);
  const rawExpiry = String(registration.expires_at ?? "");
  const active = /^\d+$/.test(rawExpiry)
    ? BigInt(rawExpiry) > BigInt(Date.now()) * 1_000_000n
    : Number.isFinite(Date.parse(rawExpiry)) && Date.parse(rawExpiry) > Date.now();
  if (!active) throw new Error(`Sworn registration for ${model} is expired or has no readable expiry`);
  const prompt = dossierPrompt(bundle);
  const requestBytes = Buffer.from(JSON.stringify({
    messages: [{ role: "user", content: `[salt ${randomUUID().replaceAll("-", "")}] ${prompt}` }],
    max_tokens: 2048,
    response_format: { type: "json_object" },
    chat_template_kwargs: { enable_thinking: false },
    model,
    stream: false,
  }));
  const request = JSON.parse(requestBytes.toString("utf8"));
  const clock = { start: Date.now() };
  const completionResponse = await fetch("https://cloud-api.near.ai/v1/chat/completions", {
    method: "POST", headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json", "accept-encoding": "identity", "x-no-aliasing": "true" },
    body: requestBytes, signal: AbortSignal.timeout(90000),
  });
  if (!completionResponse.ok) throw new Error(`NEAR AI completion HTTP ${completionResponse.status}: ${(await completionResponse.text()).slice(0, 300)}`);
  const responseBytes = Buffer.from(await completionResponse.arrayBuffer());
  const completion = JSON.parse(responseBytes.toString("utf8"));
  if (completion.model !== model) throw new Error(`NEAR AI returned model ${completion.model}, expected ${model}`);
  clock.completion_ms = Date.now() - clock.start;
  const signatureUrl = `https://cloud-api.near.ai/v1/signature/${encodeURIComponent(completion.id)}?signing_algo=ed25519`;
  let receipt;
  const receiptStart = Date.now();
  for (let i = 0; i < 10; i += 1) {
    clock.receipt_attempts = i + 1;
    if (i) await new Promise(resolve => setTimeout(resolve, 1000));
    const response = await fetch(signatureUrl, { headers: { authorization: `Bearer ${apiKey}`, "accept-encoding": "identity" }, signal: AbortSignal.timeout(10000) });
    if (!response.ok) continue;
    const candidate = await response.json();
    if (candidate.signature) { receipt = candidate; break; }
  }
  clock.receipt_ms = Date.now() - receiptStart;
  if (!receipt) throw new Error("NEAR AI provider TEE signature unavailable after 10 attempts");
  const reqHash = createHash("sha256").update(requestBytes).digest("hex");
  const resHash = createHash("sha256").update(responseBytes).digest("hex");
  const signedText = `${model}:${reqHash}:${resHash}`;
  if (receipt.signature_kind !== "provider_tee" || receipt.signing_algo !== "ed25519" || receipt.text !== signedText) throw new Error("Sworn provider receipt refused: kind, algorithm, or signed bytes do not match");
  const pub = Buffer.from(receipt.signing_address.replace(/^0x/, ""), "hex");
  const sig = Buffer.from(receipt.signature.replace(/^0x/, ""), "hex");
  if (pub.length !== 32 || sig.length !== 64) throw new Error("Sworn provider receipt has invalid key or signature length");
  const verifier = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]), format: "der", type: "spki" });
  if (!verifySignature(null, Buffer.from(signedText), verifier, sig)) throw new Error("Sworn provider receipt signature invalid");
  if (registration.public_key !== receipt.signing_address.replace(/^0x/, "")) throw new Error("NEAR AI signing key does not match the Sworn registration");
  const receiptView = { model, registry: REGISTRY, registered_key: registration.public_key, request_sha256: reqHash, response_sha256: resHash, signature: receipt.signature, request_bytes: requestBytes.length, response_bytes: responseBytes.length, timings_ms: { completion: clock.completion_ms, receipt: clock.receipt_ms } };
  await onStage({ stage: "enclave", ...receiptView });
  const verdictBlock = {};
  const verdict = await view(REGISTRY, "check", {
    public_key: receipt.signing_address.replace(/^0x/, ""), model_id: model,
    request_sha256: reqHash, response_sha256: resHash, signature: receipt.signature.replace(/^0x/, ""),
    required_platform: null, required_app_id: null,
  }, verdictBlock);
  await onStage({ stage: "check", verdict, block: verdictBlock });
  if (!verdict.ok) throw new Error(`Sworn registry refused the response: ${verdict.reason ?? "unknown reason"}`);
  const content = completion.choices?.[0]?.message?.content;
  if (typeof content !== "string" || !content.trim()) {
    if (completion.choices?.[0]?.finish_reason === "length") throw new Error("NEAR AI response reached its token limit before returning dossier JSON");
    throw new Error("NEAR AI response has no text content");
  }
  let dossier;
  try { dossier = JSON.parse(content); } catch { throw new Error("NEAR AI response is not valid JSON"); }
  return { dossier, attestation: { registry: REGISTRY, model, registered_key: registration.public_key, registration, verdict, verdict_block: verdictBlock, timings_ms: { completion: clock.completion_ms, receipt: clock.receipt_ms, receipt_attempts: clock.receipt_attempts }, request_sha256: reqHash, response_sha256: resHash, signature: receipt.signature } };
}

export async function recheckReceipt(attestation) {
  const verdictBlock = {};
  const verdict = await view(attestation.registry, "check", {
    public_key: attestation.registered_key, model_id: attestation.model,
    request_sha256: attestation.request_sha256, response_sha256: attestation.response_sha256, signature: attestation.signature,
    required_platform: null, required_app_id: null,
  }, verdictBlock);
  return { ...attestation, verdict, verdict_block: verdictBlock };
}

async function view(accountId, method, args, at = {}) {
  const result = await rpc("testnet", "query", { request_type: "call_function", account_id: accountId, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString("base64"), finality: "final" });
  at.block_height = result.block_height;
  at.block_hash = result.block_hash;
  return JSON.parse(Buffer.from(result.result).toString("utf8"));
}

export async function confidentialQuote({ recipient, refundTo = recipient, originAsset, destinationAsset = "nep141:wrap.near", amount, accessToken }) {
  if (!/^[0-9]+$/.test(amount) || BigInt(amount) <= 0n) throw new Error("amount must be a positive integer in base units");
  if (typeof accessToken !== "string" || !accessToken) throw new Error("1Click user-session token required for confidential quotes");
  const request = {
    dry: false, swapType: "EXACT_INPUT", slippageTolerance: 100,
    originAsset, depositType: "ORIGIN_CHAIN", destinationAsset, amount,
    refundTo, refundType: "ORIGIN_CHAIN", recipient, recipientType: "CONFIDENTIAL_INTENTS",
    deadline: new Date(Date.now() + 15 * 60_000).toISOString(), confidentiality: "basic",
  };
  return jsonFetch("https://1click.chaindefuser.com/v0/quote", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` }, body: JSON.stringify(request) });
}

export async function readJson(path) {
  const { readFile } = await import("node:fs/promises");
  return JSON.parse(await readFile(path, "utf8"));
}

export async function mainnetOwnership(proof) {
  return verifyAccountOwnership(proof, "mainnet");
}

const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u128 = n => { const b = Buffer.alloc(16); b.writeBigUInt64LE(BigInt(n) & 0xffffffffffffffffn); b.writeBigUInt64LE(BigInt(n) >> 64n, 8); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

export function encodeFunctionCallTx({ signerId, publicKey, nonce, receiverId, blockHash, methodName, args, gas, deposit = 0n }) {
  const key = decodeBase58(publicKey.replace(/^ed25519:/, ""));
  const hash = decodeBase58(blockHash);
  if (key.length !== 32 || hash.length !== 32) throw new Error("transaction key or block hash has the wrong length");
  const argBytes = Buffer.from(args);
  return Buffer.concat([
    borshString(signerId), Buffer.from([0]), key, u64(nonce), borshString(receiverId), hash,
    u32(1), Buffer.from([2]), borshString(methodName), u32(argBytes.length), argBytes, u64(gas), u128(deposit),
  ]);
}

export function signedTxBase64(txBytes, privateKey) {
  const signature = signBytes(null, createHash("sha256").update(txBytes).digest(), privateKey);
  return Buffer.concat([txBytes, Buffer.from([0]), signature]).toString("base64");
}

const lastNonce = new Map();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const transient = error => /HTTP 429|HTTP 5\d\d|Rate limit|timed out|timeout|fetch failed|aborted|ECONN/i.test(error.message);

export async function sendFunctionCall({ network = "testnet", signerId, publicKey, privateKey, receiverId, methodName, args, gas = 30_000_000_000_000n, deposit = 0n }) {
  let failure;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (failure && transient(failure)) await sleep(700 * attempt);
    let key;
    try { key = await rpc(network, "query", { request_type: "view_access_key", finality: "final", account_id: signerId, public_key: publicKey }); }
    catch (error) { failure = error; if (transient(error)) continue; throw error; }
    const nonce = Math.max(Number(key.nonce), lastNonce.get(signerId) ?? 0) + 1;
    lastNonce.set(signerId, nonce);
    const tx = encodeFunctionCallTx({ signerId, publicKey, nonce, receiverId, blockHash: key.block_hash, methodName, args: JSON.stringify(args), gas, deposit });
    try {
      return await rpc(network, "send_tx", { signed_tx_base64: signedTxBase64(tx, privateKey), wait_until: "FINAL" });
    } catch (error) {
      failure = error;
      if (/InvalidNonce|nonce/i.test(error.message)) { lastNonce.delete(signerId); await sleep(150 + Math.floor(Math.random() * 350)); continue; }
      if (!transient(error)) throw error;
    }
  }
  throw failure;
}

export const txUrl = (network, hash) => `https://${network === "testnet" ? "testnet." : ""}nearblocks.io/txns/${hash}`;

export async function verifyOnChain({ attestation, signerId, publicKey, privateKey, network = "testnet" }) {
  const started = Date.now();
  const outcome = await sendFunctionCall({
    network, signerId, publicKey, privateKey, receiverId: attestation.registry, methodName: "verify",
    args: {
      public_key: attestation.registered_key, model_id: attestation.model, request_sha256: attestation.request_sha256,
      response_sha256: attestation.response_sha256, signature: attestation.signature.replace(/^0x/, ""), required_platform: null, required_app_id: null,
    },
  });
  if (outcome.status?.Failure) throw new Error(`Sworn verify transaction failed: ${JSON.stringify(outcome.status.Failure).slice(0, 300)}`);
  const verdict = JSON.parse(Buffer.from(outcome.status.SuccessValue ?? "", "base64").toString("utf8") || "null");
  const logs = outcome.receipts_outcome.flatMap(r => r.outcome.logs);
  const event = logs.map(l => l.replace(/^EVENT_JSON:/, "")).map(l => { try { return JSON.parse(l); } catch { return null; } }).find(e => e?.event === "verify") ?? null;
  const lastReceipt = outcome.receipts_outcome.at(-1);
  const block = await rpc(network, "block", { block_id: lastReceipt.block_hash }).catch(() => null);
  return {
    tx_hash: outcome.transaction.hash, signer_id: signerId, receiver_id: attestation.registry, method: "verify", explorer: txUrl(network, outcome.transaction.hash),
    verdict, event, block_height: block?.header?.height ?? null, block_hash: lastReceipt.block_hash,
    gas_burnt: outcome.receipts_outcome.reduce((sum, r) => sum + BigInt(r.outcome.gas_burnt), BigInt(outcome.transaction_outcome.outcome.gas_burnt)).toString(),
    tokens_burnt_yocto: outcome.receipts_outcome.reduce((sum, r) => sum + BigInt(r.outcome.tokens_burnt), BigInt(outcome.transaction_outcome.outcome.tokens_burnt)).toString(),
    elapsed_ms: Date.now() - started,
  };
}
