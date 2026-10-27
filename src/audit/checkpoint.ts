/**
 * Signed checkpoints for the audit chain.
 *
 * The hash chain shows that records inside a log were not edited, but not that the newest records
 * were not cut off. A checkpoint is a signed statement of the chain head ("run R had N events up to
 * seq S, ending in hash H"). Sent to a second sink the attacker cannot rewrite (a witness), it makes
 * a cut detectable back to the last checkpoint that reached the witness.
 *
 * Ed25519 (node:crypto, no dependency): verifiers need only the public key and cannot forge one.
 *
 * @packageDocumentation
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import { canonicalize } from "./chain.js";
import type { AuditCheckpoint } from "./types.js";

/** First 16 hex chars of SHA-256 over the public key's SPKI DER: names the key in each checkpoint. */
export function keyIdOf(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

/** A fresh Ed25519 key pair as PEM (PKCS#8 private, SPKI public). */
export function generateCheckpointKeyPair(): {
  privateKeyPem: string;
  publicKeyPem: string;
  keyId: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    keyId: keyIdOf(publicKey),
  };
}

const signedBytes = (cp: Omit<AuditCheckpoint, "sig">): Buffer =>
  Buffer.from(canonicalize(cp), "utf8");

export class CheckpointSigner {
  private readonly privateKey: KeyObject;
  readonly keyId: string;

  /** @param privateKeyPem An Ed25519 private key (PKCS#8 PEM). */
  constructor(privateKeyPem: string) {
    let key: KeyObject;
    try {
      key = createPrivateKey(privateKeyPem);
    } catch (err) {
      throw new Error(
        `audit checkpoint key is not a valid private key: ${(err as Error).message}`,
        { cause: err },
      );
    }
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `audit checkpoint key must be Ed25519, got ${key.asymmetricKeyType ?? "unknown"}`,
      );
    }
    this.privateKey = key;
    this.keyId = keyIdOf(createPublicKey(key));
  }

  /** Build and sign a checkpoint for the given chain head. */
  sign(head: {
    runId: string;
    seq: number;
    head: string;
    count: number;
    ts?: string;
  }): AuditCheckpoint {
    const body: Omit<AuditCheckpoint, "sig"> = {
      recordType: "checkpoint",
      runId: head.runId,
      seq: head.seq,
      head: head.head,
      count: head.count,
      ts: head.ts ?? new Date().toISOString(),
      keyId: this.keyId,
    };
    return { ...body, sig: sign(null, signedBytes(body), this.privateKey).toString("base64url") };
  }
}

/** Verify one checkpoint's signature against a public key (PEM or KeyObject). */
export function verifyCheckpoint(cp: AuditCheckpoint, publicKey: string | KeyObject): boolean {
  try {
    const key = typeof publicKey === "string" ? createPublicKey(publicKey) : publicKey;
    if (keyIdOf(key) !== cp.keyId) return false;
    const { sig, ...body } = cp;
    return verify(null, signedBytes(body), key, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
}
