Claim: A SHA-256 digest of a NEP-413 Borsh payload signed by a testnet account's FullAccess key verifies in under 1 second, while a one-bit signature mutation is rejected.
Verdict: CONFIRMED
Measured: 0.39 seconds wall time; `node spikes/nep413-owner/spike.mjs` printed `permission: FullAccess`, `signature: valid`, and `forgedSignature: refused` after querying `https://near-testnet.drpc.org`.
Negative case: Flip bit 0 of the generated 64-byte Ed25519 signature; Node's verifier rejects it. A non-FullAccess key is not accepted by the account permission check.
Caveat: The signing key is the locally generated faucet account key, not a browser wallet response. The test encodes the NEP-413 tag and payload Borsh fields from the spec; interoperability still needs a browser wallet response exercised. Account ID and permission were observed on testnet, not mainnet.
Blocks product: no

Research: NEP-413 defines the payload and off-chain Borsh domain separator (`2^31 + 413`) and requires a FullAccess key: https://github.com/near/NEPs/blob/master/neps/nep-0413.md. The exact 1Click NEP-413 signing flow is documented at https://docs.near-intents.org/integration/verifier-contract/signing-intents.
