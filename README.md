# Wrench: audit your wallet privately

[![judge](https://github.com/CryptoInnovators/near-wrench/actions/workflows/judge.yml/badge.svg)](https://github.com/CryptoInnovators/near-wrench/actions/workflows/judge.yml)

A model reads your NEAR account's exposure inside a TEE. NEAR's Sworn registry verifies the model's signed receipt in a real testnet transaction before you see a word. Lead track: Privacy and Private AI. Also fits Security and DeFi.

Live (NEAR testnet, no wallet needed): https://near-wrench.earn-shield-alerts.workers.dev

## Do this, see that (60 seconds)

1. Open the live URL and press `Audit a demo wallet`. In about 25 seconds the page fills three bands: `What left your browser` (one NEP-413 signature), `What the enclave saw` (public balance, transactions, counterparties, the enclave's signed request and response hashes) and `What the chain shows` (a `verify()` transaction on `sworn-reg7-1113.testnet` with a link that opens on testnet.nearblocks.io, `ok:true`). The dossier unseals below after that transaction returns.
2. Press `Send a tampered receipt`. Wrench flips one bit of the response hash and sends it to `verify()`. See `Refused on chain`, `ok:false`, and the transaction link.
3. Under `Claim an account you do not own` press `Claim it` with `near.testnet`. See `Refused`: the signature is valid, the account's keys do not include the signer, and no data was collected.
4. Under `Review your own account`, pick Testnet, press `Connect wallet and sign` (Meteor, Intear, MyNearWallet and others through near-connect) and the same three bands run on your account. `Sign somewhere else and paste the result` accepts any NEP-413 signature. Mainnet adds a confidential 1Click quote.

## AI judges

```
node scripts/judge.mjs   # 9 checks against the live URL: tests, page, registry code hash, 3 evidence txs, a live run that lands a new verify() tx, refusal, tamper
bash scripts/test.sh     # offline: NEP-413, transaction encoding, RPC fallover, forged signatures refused
```

Evidence with transaction links: [docs/EVIDENCE.md](docs/EVIDENCE.md). Company summary: [COMPANY.md](COMPANY.md).

## How the privacy holds

- Ownership: a fresh 32-byte nonce per request, a five-minute challenge, one use. The signing key must be a FullAccess key of the account on NEAR RPC.
- Model: `Qwen/Qwen3.8-27B` on NEAR AI Cloud, called with a salted prompt over public data only. Your key and seed never reach Wrench.
- Attestation: the provider TEE ed25519 receipt covers the exact request and response SHA-256 hashes, its key matches the live registration in `sworn-reg7-1113.testnet`, and `verify()` records the verdict on chain.
- On chain: two hashes and a signature. The dossier text stays off chain.

## Tracks

Lead: Privacy and Private AI. Also fits: Security (owner-gated, forged signatures and tampered receipts refused) and DeFi (confidential 1Click quote for mainnet accounts).

## Same builder's other project

Q-015: <other project, to be assigned by the owner>
