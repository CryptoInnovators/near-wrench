# Wrench

Audit your wallet privately: a model reads your account's exposure inside a TEE, and NEAR's Sworn registry verifies its signed receipt in a real transaction before you see a word.

## Who uses it

NEAR account owners who want to see what their own wallet gives away, and want proof the analysis came from the attested model and was not edited on the way back. Security-minded DAOs and treasuries get the same dossier for any account they can sign for.

## How it works

1. You sign one NEP-413 message (a fresh 32-byte nonce, five-minute window, one use). Wrench checks on NEAR RPC that the signing key is a FullAccess key of the account. An unowned account is refused before any data moves.
2. Public account data (balance, recent transactions, counterparties, access keys) goes to `Qwen/Qwen3.8-27B` on NEAR AI Cloud, which runs inside a TEE. Your key and seed never leave your wallet.
3. The enclave signs request and response hashes. Wrench checks that signature against the key registered in `sworn-reg7-1113.testnet` with the `check()` view.
4. Wrench sends `verify()` to the registry as a real testnet transaction. The registry logs the verdict. Only two hashes and a signature go on chain; the dossier text stays off chain.
5. The dossier is released after the transaction returns `ok:true`: a stamp with the transaction, the facts read from chain, and findings ranked by severity (an extra FullAccess key ranks high). A receipt with one flipped bit comes back `ok:false` in its own transaction.

## Evidence

| Fact | Evidence |
| --- | --- |
| A cold click on the hosted page runs the whole review and lands a `verify()` transaction in 17.1 s | [7A673VZz…](https://testnet.nearblocks.io/txns/7A673VZzq65fLrjvjSNGH87HHf3cDUG6CBzJd41LfbEX) returned `ok:true`, `verified`; earlier cold runs [5gtsaR6e…](https://testnet.nearblocks.io/txns/5gtsaR6eAoqjpdtXvP9Xj8Hqnj42NxAdF7WoitNR8ZwQ) in 26.3 s and [DU2JDSeS…](https://testnet.nearblocks.io/txns/DU2JDSeSUx7kc8MHN1ADDkqz2LyW9PMpsY7PRDZVQbQV) in 25.1 s |
| A wallet-path review (NEP-413 signature pasted into the page) completes on testnet | [CgS9yrwj…](https://testnet.nearblocks.io/txns/CgS9yrwjzRUeoHo2kxuagRpoVckzK6M69bTBEPtgjvzN) returned `ok:true` in 25.7 s |
| A tampered receipt is refused on chain | [7fcG8P6A…](https://testnet.nearblocks.io/txns/7fcG8P6AV3Z8wYHP8j8JH1HRGViSiCqrdnuUdkG2tKfa) returned `ok:false`, `signature does not verify over model:request:response` |
| A valid signature does not open an account the key does not control | `node scripts/judge.mjs` runs the live `/api/demo-unowned` refusal for `near.testnet` |
| The registry is deployed on testnet | `sworn-reg7-1113.testnet`, code hash read by `node scripts/judge.mjs` |
| Transaction encoding, NEP-413 verification and RPC fallover are mutation-checked | `bash scripts/test.sh`; breaking the action tag or dropping the fallback RPC turns it red |
| Nine judge checks run on every push against the live URL | `node scripts/judge.mjs`, workflow `.github/workflows/judge.yml` |

More txs and the failure cases: [docs/EVIDENCE.md](docs/EVIDENCE.md).

## Try it in 60 seconds

Open https://near-wrench.earn-shield-alerts.workers.dev and press `Audit a demo wallet`. No wallet needed. In about 25 seconds the three bands fill with what left your browser, what the enclave saw, and the `verify()` transaction link. Then press `Tamper with this receipt` in the green band and watch the chain refuse it, or `Post result on X` to share the outcome.

## Why NEAR

NEAR AI Cloud gives a model that runs in a TEE and signs its output. The Sworn registry on NEAR holds the enclave key and verifies the receipt on chain, so the check is a transaction anyone can open, not a claim. NEP-413 gives the ownership proof with the wallet the user already has. 1Click adds a confidential balance move for the mainnet account.

## Team and build window

Built by `kamalbuilds` from 2026-11-13 to 2026-11-14 (`git log --reverse --format='%ad %an' --date=short`).
