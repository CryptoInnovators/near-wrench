# Wrench: audit your wallet exposure privately, on a TEE

Wrench lets a NEAR account owner prove ownership with a NEP-413 signature, has a model on NEAR AI Cloud analyse that account's public exposure inside a TEE, and verifies the TEE-signed receipt against the on-chain Sworn registry before showing the dossier, then quotes a confidential 1Click transfer to act on it.

## 60-second judge path

1. `bash scripts/serve.sh` starts the app locally (the NEAR AI key is read from the local env file, never from the page).
2. Open the printed local URL, enter a testnet account, sign the NEP-413 challenge, and read the dossier and its Verified attestation block.
3. Try an account you do not own: the signature check refuses it.

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
