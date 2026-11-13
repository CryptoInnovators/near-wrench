import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const rpc = "https://near-testnet.drpc.org";
const accountId = "wrenchaudit1113.testnet";
const credential = JSON.parse(readFileSync(`${process.env.HOME}/.near-credentials/testnet/wrench.audit-1113.testnet.json`, "utf8"));
const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function decode58(text) {
  let n = 0n;
  for (const c of text) n = n * 58n + BigInt(b58.indexOf(c));
  const bytes = n ? [...Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, "0"), "hex")] : [];
  for (const c of text) { if (c !== "1") break; bytes.unshift(0); }
  return Buffer.from(bytes);
}
function len(bytes) { const out = Buffer.alloc(4); out.writeUInt32LE(bytes.length); return out; }
function payloadBytes(payload) {
  const msg = Buffer.from(payload.message);
  const recipient = Buffer.from(payload.recipient);
  return Buffer.concat([Buffer.from([0x9d, 0x01, 0, 0x80]), len(msg), msg, Buffer.from(payload.nonce), len(recipient), recipient, Buffer.from([0])]);
}
const nonce = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
const payload = { message: "Wrench ownership check", nonce, recipient: "wrench.local" };
const secret = decode58(credential.private_key.slice("ed25519:".length)).subarray(0, 32);
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), secret]), format: "der", type: "pkcs8" });
const publicKey = createPublicKey(privateKey);
const digest = createHash("sha256").update(payloadBytes(payload)).digest();
const signed = sign(null, digest, privateKey);
assert.equal(signed.length, 64);
assert.equal(verify(null, digest, publicKey, signed), true);
const forged = Buffer.from(signed);
forged[0] ^= 1;
assert.equal(verify(null, digest, publicKey, forged), false);

const [keyType, keyValue] = credential.public_key.split(":");
assert.equal(keyType, "ed25519");
const keyBytes = decode58(keyValue);
const accessKey = await fetch(rpc, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: "wrench-spike", method: "query", params: { request_type: "view_access_key", finality: "final", account_id: accountId, public_key: credential.public_key } }),
}).then(async response => {
  assert.equal(response.ok, true, `RPC HTTP ${response.status}`);
  const result = await response.json();
  assert.equal(result.error, undefined, JSON.stringify(result.error));
  return result.result;
});
assert.equal(accessKey.permission, "FullAccess");
assert.equal(keyBytes.length, 32);
console.log(JSON.stringify({ accountId, permission: "FullAccess", signature: "valid", forgedSignature: "refused", publicKeyBytes: keyBytes.length }));
