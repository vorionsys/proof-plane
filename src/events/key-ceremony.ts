/**
 * Key Ceremony Log — Types and utilities for cryptographic key ceremony documentation.
 *
 * Every production signing key must have a completed ceremony log that records
 * who generated it, under what controls, and who witnessed the process.
 * See docs/security/KEY-CEREMONY-PROCEDURE.md for the full procedure.
 *
 * @packageDocumentation
 */

import { sha256 } from './hash-chain.js';
import { signEvent, verifyEventSignature } from './event-signatures.js';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Environment in which a key ceremony was conducted.
 */
export type CeremonyEnvironment = 'airgapped' | 'hsm' | 'cloud-hsm';

/**
 * Role a participant plays in a key ceremony.
 */
export type CeremonyRole = 'custodian' | 'witness' | 'security_officer';

/**
 * A witness or participant who countersigned the ceremony log.
 */
export interface KeyCeremonyWitness {
  /** Full name of the witness */
  name: string;
  /** Role in the ceremony */
  role: CeremonyRole;
  /** ISO 8601 timestamp when the witness signed */
  signedAt: string;
  /** PGP signature, Ed25519 signature, or SHA-256 hash of scanned handwritten signature */
  signature: string;
}

/**
 * Shamir's Secret Sharing configuration used to split the private key.
 * Only present when the key was NOT generated in an HSM.
 */
export interface ShamirConfig {
  /** Minimum shares needed to reconstruct the key */
  threshold: number;
  /** Total number of shares generated */
  totalShares: number;
  /** Names or descriptions of share recipients — NEVER share material */
  shareRecipients: string[];
}

/**
 * Complete ceremony log for a cryptographic key generation event.
 *
 * This record provides auditable provenance for every production signing key.
 * It answers: who generated the key, where, when, and under what controls.
 */
export interface KeyCeremonyLog {
  /** Unique identifier for this ceremony (UUID v4) */
  ceremonyId: string;
  /** Key identifier, matches KeyMetadata.id in key-rotation.ts */
  keyId: string;
  /** Cryptographic algorithm used */
  algorithm: 'Ed25519';
  /** SHA-256 fingerprint of the public key (hex-encoded) */
  keyFingerprint: string;
  /** ISO 8601 timestamp of key generation */
  createdAt: string;
  /** Name of the Key Custodian who generated the key */
  custodian: {
    name: string;
    role: 'custodian';
  };
  /** Witnesses and other participants who observed and countersigned */
  witnesses: KeyCeremonyWitness[];
  /** HSM serial number, if key was generated in an HSM */
  hsmSerial?: string;
  /** Environment where the ceremony was conducted */
  environment: CeremonyEnvironment;
  /** Version of the ceremony procedure followed */
  procedureVersion: string;
  /** Shamir's Secret Sharing configuration, if used */
  shamirConfig?: ShamirConfig;
  /** Ed25519 signature of this log by the newly generated key (self-attestation) */
  selfAttestation?: string;
  /** Free-form notes (backup verification, special circumstances, etc.) */
  notes?: string;
  /** SHA-256 hash of the serialized log (computed with this field set to empty string) */
  ceremonyHash?: string;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Create a new ceremony log with required fields populated.
 *
 * Usage:
 * ```typescript
 * const log = createCeremonyLog({
 *   keyId: 'agentanchor-prod-001',
 *   keyFingerprint: 'abcdef1234567890...',
 *   custodianName: 'Jane Smith',
 *   environment: 'airgapped',
 * });
 * ```
 */
export function createCeremonyLog(params: {
  keyId: string;
  keyFingerprint: string;
  custodianName: string;
  environment: CeremonyEnvironment;
  hsmSerial?: string;
  shamirConfig?: ShamirConfig;
  notes?: string;
}): KeyCeremonyLog {
  return {
    ceremonyId: crypto.randomUUID(),
    keyId: params.keyId,
    algorithm: 'Ed25519',
    keyFingerprint: params.keyFingerprint,
    createdAt: new Date().toISOString(),
    custodian: {
      name: params.custodianName,
      role: 'custodian',
    },
    witnesses: [],
    hsmSerial: params.hsmSerial,
    environment: params.environment,
    procedureVersion: '1.0',
    shamirConfig: params.shamirConfig,
    notes: params.notes,
  };
}

// ─── Witness Management ───────────────────────────────────────────────────────

/**
 * Add a witness countersignature to a ceremony log.
 * Returns a new log (does not mutate the original).
 */
export function addWitness(
  log: KeyCeremonyLog,
  witness: KeyCeremonyWitness
): KeyCeremonyLog {
  return {
    ...log,
    witnesses: [...log.witnesses, witness],
  };
}

// ─── Hashing ──────────────────────────────────────────────────────────────────

/**
 * Compute the ceremony hash (SHA-256 of the serialized log with ceremonyHash set to empty string).
 * This provides self-referential integrity for the log.
 */
export async function computeCeremonyHash(log: KeyCeremonyLog): Promise<string> {
  const hashable = { ...log, ceremonyHash: '' };
  const serialized = JSON.stringify(hashable, Object.keys(hashable).sort());
  return sha256(serialized);
}

/**
 * Finalize a ceremony log by computing and setting its ceremonyHash.
 * Call this after all witnesses have signed and self-attestation is complete.
 * Returns a new log with the ceremonyHash set.
 */
export async function finalizeCeremonyLog(log: KeyCeremonyLog): Promise<KeyCeremonyLog> {
  const hash = await computeCeremonyHash(log);
  return { ...log, ceremonyHash: hash };
}

// ─── Self-Attestation ─────────────────────────────────────────────────────────

/**
 * Sign the ceremony log with the newly generated key (self-attestation).
 * This proves the key was functional at ceremony time.
 *
 * @param log - The ceremony log to sign
 * @param privateKeyBase64 - The newly generated private key (base64)
 * @returns The log with selfAttestation populated
 */
export async function attestCeremonyLog(
  log: KeyCeremonyLog,
  privateKeyBase64: string
): Promise<KeyCeremonyLog> {
  const logData = JSON.stringify({ ...log, selfAttestation: undefined }, null, 0);

  const signature = await signEvent(
    {
      eventId: log.ceremonyId,
      eventType: 'key_ceremony' as any,
      correlationId: log.ceremonyId,
      payload: { type: 'key_ceremony' as any, data: logData } as any,
      previousHash: null,
      occurredAt: new Date(log.createdAt),
    },
    privateKeyBase64,
    'ceremony-attestation'
  );

  return { ...log, selfAttestation: signature };
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Result of verifying a ceremony log.
 */
export interface CeremonyVerificationResult {
  /** Overall validity */
  valid: boolean;
  /** Whether the ceremony hash matches */
  hashValid: boolean;
  /** Whether the self-attestation signature is valid */
  selfAttestationValid: boolean;
  /** Number of witness signatures present */
  witnessCount: number;
  /** Individual errors, if any */
  errors: string[];
}

/**
 * Verify a ceremony log's integrity.
 *
 * Checks:
 * 1. The ceremonyHash matches the serialized log content
 * 2. The self-attestation signature is valid (if present and publicKey provided)
 * 3. At least one witness is present
 * 4. Required fields are populated
 *
 * @param log - The ceremony log to verify
 * @param publicKeyBase64 - The public key to verify self-attestation against (optional)
 */
export async function verifyCeremonyLog(
  log: KeyCeremonyLog,
  publicKeyBase64?: string
): Promise<CeremonyVerificationResult> {
  const errors: string[] = [];
  let hashValid = false;
  let selfAttestationValid = false;

  // --- Structural validation ---
  if (!log.ceremonyId) errors.push('Missing ceremonyId');
  if (!log.keyId) errors.push('Missing keyId');
  if (!log.keyFingerprint) errors.push('Missing keyFingerprint');
  if (!log.createdAt) errors.push('Missing createdAt');
  if (!log.custodian?.name) errors.push('Missing custodian name');
  if (!log.environment) errors.push('Missing environment');
  if (!log.procedureVersion) errors.push('Missing procedureVersion');

  // --- Witness check ---
  if (!log.witnesses || log.witnesses.length === 0) {
    errors.push('No witnesses present — ceremony requires at least one witness');
  } else {
    for (const w of log.witnesses) {
      if (!w.name) errors.push('Witness missing name');
      if (!w.signature) errors.push(`Witness ${w.name || '(unnamed)'} missing signature`);
      if (!w.signedAt) errors.push(`Witness ${w.name || '(unnamed)'} missing signedAt`);
    }
  }

  // --- Hash verification ---
  if (log.ceremonyHash) {
    const expectedHash = await computeCeremonyHash(log);
    hashValid = log.ceremonyHash === expectedHash;
    if (!hashValid) {
      errors.push(
        `Ceremony hash mismatch: expected ${expectedHash}, got ${log.ceremonyHash}`
      );
    }
  } else {
    errors.push('No ceremonyHash present — log has not been finalized');
  }

  // --- Self-attestation verification ---
  if (log.selfAttestation && publicKeyBase64) {
    const logData = JSON.stringify({ ...log, selfAttestation: undefined }, null, 0);
    const event = {
      eventId: log.ceremonyId,
      eventType: 'key_ceremony' as any,
      correlationId: log.ceremonyId,
      payload: { type: 'key_ceremony' as any, data: logData } as any,
      previousHash: null,
      occurredAt: new Date(log.createdAt),
      recordedAt: new Date(log.createdAt),
      eventHash: await sha256(logData),
      signedBy: 'ceremony-attestation',
      signature: log.selfAttestation,
    };

    const result = await verifyEventSignature(event, publicKeyBase64);
    selfAttestationValid = result.valid;
    if (!result.valid) {
      errors.push(`Self-attestation verification failed: ${result.error || 'invalid signature'}`);
    }
  } else if (log.selfAttestation && !publicKeyBase64) {
    // Self-attestation present but no public key provided — cannot verify
    errors.push('Self-attestation present but no public key provided for verification');
  } else if (!log.selfAttestation) {
    errors.push('No self-attestation signature — key functionality not proven');
  }

  return {
    valid: errors.length === 0,
    hashValid,
    selfAttestationValid,
    witnessCount: log.witnesses?.length ?? 0,
    errors,
  };
}
