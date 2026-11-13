# Wrench: audit your wallet exposure privately, on a TEE

Wrench lets a NEAR account owner prove ownership with a NEP-413 signature, has a model on NEAR AI Cloud analyse that account's public exposure inside a TEE, and verifies the TEE-signed receipt against the on-chain Sworn registry before showing the dossier, then quotes a confidential 1Click transfer to act on it.

## 60-second judge path

Live: https://near-wrench.earn-shield-alerts.workers.dev (NEAR testnet, no wallet needed)

1. Press `Run the demo review`. Wrench signs a NEP-413 challenge for the testnet demo account `wrenchauditdemo1113.wrenchaudit1113.testnet`, checks that key against the account's FullAccess keys over RPC, has `Qwen/Qwen3.8-27B` on NEAR AI Cloud read the account inside a TEE, and verifies the TEE-signed receipt with the `check()` view of `sworn-reg7-1113.testnet`. The `On-chain result` block shows `ok:true`, the block it was read at, the registered key, and the request and response SHA-256.
2. Type `near.testnet` under `Try an account you do not own`. The signature is cryptographically valid and Wrench refuses the account before any data is collected or any model is called.
3. Press `Run a fresh model call` for a new TEE-signed completion and a new registry check.
4. With your own wallet, `Connect and sign` runs the same review on your account, then quotes a confidential 1Click transfer. Run it locally with `bash scripts/serve.sh`.

Hosted limits: per-visitor and daily caps on model calls keep the public URL within budget; over the cap the page shows the latest attested review and re-runs the on-chain check live.

## AI judges

Run `bash scripts/test.sh` from a clean clone. It replays a recorded testnet account (`wrenchauditdemo1113.wrenchaudit1113.testnet`) and checks the NEP-413 signature, the account binding, refusal of a one-bit forged signature, refusal of a signature relabelled to another account, and that the confidential 1Click quote requires a user-session token.

## Tracks

Lead: Privacy and Private AI. Also fits: Security (owner-gated, forged signatures refused) and DeFi (confidential 1Click quote).

## Same builder's other project

Q-015: <other project, to be assigned by the owner>

## How the privacy holds

- Ownership: a fresh 32-byte nonce per request, a five-minute challenge, one use.
- Model: `Qwen/Qwen3.8-27B` on NEAR AI Cloud, called with a salted prompt.
- Attestation: the provider TEE ed25519 receipt must cover the exact request and response SHA-256 hashes, and its key must match the live registration in `sworn-reg7-1113.testnet`, which must be unexpired and return a passing check.
