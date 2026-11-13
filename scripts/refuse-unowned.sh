#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --input-type=module <<'NODE'
import assert from "node:assert/strict";
import { readJson, proofBindsAccount, verifyAccountOwnership, verifyNep413 } from "./scripts/wrench.mjs";
const fixture = await readJson("./fixtures/wrenchaudit1113/public-data.json");
const owned = await verifyAccountOwnership(fixture.proof, "testnet");
assert.equal(owned.permission, "FullAccess");
console.log(`VALID SIGNATURE PASSED: ${owned.account_id} at block ${owned.block_height}`);
const forged = fixture.unowned_proof;
assert.equal(verifyNep413(forged), true, "negative case uses a valid signature");
assert.equal(proofBindsAccount(forged), true, "negative case signature authorizes the address it claims");
let refused = false;
try { await verifyAccountOwnership(forged, "testnet"); } catch { refused = true; }
assert.equal(refused, true, "unowned target must be refused before data collection");
console.log("VALID SIGNATURE FOR UNOWNED ADDRESS REFUSED: RPC ownership check blocked dossier collection");
NODE
