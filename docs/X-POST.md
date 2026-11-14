# X demo post drafts

The human edits and posts these. Attach the demo video. X counts any link as 23 characters, and the counts below assume that.

## A (263 characters)

```
Auditing your wallet shouldn't mean handing it to a dashboard.

Built at #NEARHackathon: Wrench. A model reads your NEAR account inside a TEE, and Sworn verifies its signed receipt in a real testnet tx before you see a word.

https://near-wrench.nearlive.workers.dev @NEARProtocol
```

## B (279 characters)

```
Press Audit a demo wallet. About 25 seconds later: the signature that left your browser, what the enclave saw, and a verify() tx on testnet with ok:true. Then flip one bit of the receipt and the chain says ok:false.

Built at #NEARHackathon. https://near-wrench.nearlive.workers.dev @NEARProtocol
```

## C (257 characters)

```
Claim near.testnet with a valid NEP-413 signature and Wrench refuses: the account's keys do not include the signer, and no data is collected.

Built at #NEARHackathon: private wallet audits with NEAR AI Cloud and Sworn. https://github.com/CryptoInnovators/near-wrench @NEARProtocol
```

## Long form

```
Most wallet audits start with pasting your address into someone's dashboard and trusting the answer.

We built Wrench at #NEARHackathon so the answer arrives with proof. You sign one NEP-413 message. Wrench checks the key is a FullAccess key of the account, then a model on NEAR AI Cloud reads the account's public balance, transactions, counterparties and access keys. The provider's TEE receipt covers the exact request and response hashes, and the Sworn registry verifies it in a verify() transaction on sworn-reg7-1113.testnet before the dossier unseals. Findings are ranked by severity, such as an extra FullAccess key. Only two hashes and a signature go on chain.

Press Send a tampered receipt and one flipped bit comes back ok:false on chain. Claim an account you do not own and Wrench refuses before collecting anything.

Try it, no wallet needed: https://near-wrench.nearlive.workers.dev

@NEARProtocol @NearBuilders
```
