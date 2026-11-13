import { readJson, collectPublicData, verifyAccountOwnership, verifyLinkedAddress, requestAttestedDossier } from "./wrench.mjs";

const [proofPath, network = "mainnet"] = process.argv.slice(2);
if (!proofPath) throw new Error("usage: scripts/live-dossier.sh <signed-proof.json>");
if (!new Set(["mainnet", "testnet"]).has(network)) throw new Error("network must be mainnet or testnet");
const input = await readJson(proofPath);
const proof = input.proof ?? input;
const owner = await verifyAccountOwnership(proof, network);
const nonceHex = Buffer.from(proof.payload.nonce, "base64").toString("hex");
const linkedAddresses = [];
for (const link of proof.linkedAddresses ?? []) {
  const expected = `Authorize Wrench link ${link.chain} ${link.address} for ${proof.accountId} nonce=${nonceHex}`;
  linkedAddresses.push(await verifyLinkedAddress(link, expected));
}
const bundle = await collectPublicData(proof.accountId, network, linkedAddresses);
bundle.ownership = owner;
const result = await requestAttestedDossier(bundle, process.env.NEAR_AI_API_KEY);
console.log(JSON.stringify({ status: "ATTESTED", attestation: result.attestation, dossier: result.dossier }, null, 2));
