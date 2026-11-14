# Wrench evidence

Every row is a NEAR testnet transaction or a command anyone can run.

| Case | Result | Evidence |
| --- | --- | --- |
| Cold run on the hosted page, fresh model call | `verify()` returned `ok:true`, 25.1 s from click to final | [DU2JDSeS…](https://testnet.nearblocks.io/txns/DU2JDSeSUx7kc8MHN1ADDkqz2LyW9PMpsY7PRDZVQbQV) |
| Wallet path, signature pasted into the page, testnet account | `ok:true`, 25.7 s | [CgS9yrwj…](https://testnet.nearblocks.io/txns/CgS9yrwjzRUeoHo2kxuagRpoVckzK6M69bTBEPtgjvzN) |
| Must-fail: one bit of the response hash flipped | `ok:false`, `signature does not verify over model:request:response` | [7fcG8P6A…](https://testnet.nearblocks.io/txns/7fcG8P6AV3Z8wYHP8j8JH1HRGViSiCqrdnuUdkG2tKfa) |
| Must-fail: valid NEP-413 signature for `near.testnet` | refused before any data moves: `NEP-413 key is not a FullAccess key for this account` | `POST /api/demo-unowned {"accountId":"near.testnet"}` |
| Two visitors at the same moment | two distinct `verify()` transactions, both `ok:true` | [AmG9Ue4P…](https://testnet.nearblocks.io/txns/AmG9Ue4PDQF4kUrVqMqf6cdMgFWNsiT19PPtzwgHC6vw), [5fTp8TdaG…](https://testnet.nearblocks.io/txns/5fTp8TdaGNu1APsDV76dcvffxGH4chaGJW85ztasHegG) |
| Registry | `sworn-reg7-1113.testnet`, method `verify`, event `verify` with `ok` and `reason` | `node scripts/judge.mjs` |

## Run the checks

```
node scripts/judge.mjs        # offline tests, live page, registry code hash, three evidence txs, a live run, refusal and tamper
bash scripts/test.sh          # offline: NEP-413, transaction encoding, RPC fallover
```
