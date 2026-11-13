# Wrench

Wrench is a private wallet exposure review. The owner proves control of a NEAR account with a NEP-413 signature, a model on NEAR AI Cloud analyses the account's public activity inside a TEE, and Wrench verifies the TEE-signed receipt against the on-chain Sworn registry before the dossier is shown. A confidential 1Click quote then moves funds into confidential balances.

Live demo (testnet, no wallet): https://near-wrench.earn-shield-alerts.workers.dev

Lead track: Privacy and Private AI. Also fits Security and DeFi.

Who it is for: NEAR account owners who want to see their own exposure without handing the analysis to a party they cannot check.

What is proven: a recorded testnet account signs and verifies, forged and relabelled signatures are refused, and the quote path refuses requests without a user-session token (`bash scripts/test.sh`).
