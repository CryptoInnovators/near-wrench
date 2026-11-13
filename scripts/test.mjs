import assert from "node:assert/strict";
import { readJson, proofBindsAccount, verifyNep413 } from "./wrench.mjs";

const fixture = await readJson(new URL("../fixtures/wrenchaudit1113/public-data.json", import.meta.url));
assert.equal(fixture.network, "testnet");
assert.equal(fixture.account_id, fixture.proof.accountId);
assert.ok(BigInt(fixture.sources.rpc.account.amount) > 0n, "recorded RPC balance is real and non-zero");
assert.ok(fixture.sources.nearblocks.txns.length > 0, "recorded NearBlocks v3 history is not empty");
assert.equal(verifyNep413(fixture.proof), true, "recorded NEP-413 signature verifies");
assert.equal(proofBindsAccount(fixture.proof), true, "signed message authorizes the recorded account and nonce");
assert.equal(verifyNep413(fixture.unowned_proof), true, "negative-case signature is cryptographically valid");
assert.equal(proofBindsAccount(fixture.unowned_proof), true, "negative-case message authorizes its claimed account");

const forged = Buffer.from(fixture.proof.signature, "base64");
forged[0] ^= 1;
assert.equal(verifyNep413({ ...fixture.proof, signature: forged.toString("base64") }), false, "one-bit forged signature is refused");
assert.equal(proofBindsAccount({ ...fixture.proof, accountId: "somebodyelse.testnet" }), false, "a valid signature cannot be relabelled to another account");
assert.equal(fixture.sources.nearblocks.staking_txns.length, 0, "the captured account has no indexed staking history");

console.log(`PASS recorded public data: ${fixture.sources.nearblocks.txns.length} transaction, ${fixture.sources.nearblocks.ft_txns.length} FT transfer, ${fixture.sources.nearblocks.staking_txns.length} staking event`);
console.log("PASS NEP-413 signature, account binding, and forged-signature refusal");
console.log("PASS unowned-address negative fixture has a valid, account-bound signature");
