/**
 * Event Signatures - Ed25519 Digital Signatures for Proof Events
 *
 * Provides cryptographic signing and verification for proof events,
 * ensuring authenticity and non-repudiation in the audit trail.
 *
 * Uses Ed25519 (EdDSA) which provides:
 * - 128-bit security level
 * - Small signatures (64 bytes)
 * - Fast signing and verification
 * - Deterministic signatures (no random nonce needed)
 */

import type { ProofEvent, ProofEventPayload } from '@vorionsys/contracts';

/**
 * Signing key pair
 */
export interface SigningKeyPair {
  /** Public key in base64 format */
  publicKey: string;
  /** Private key in base64 format (keep secret!) */
  privateKey: string;
  /** Key ID for identification */
  keyId: string;
  /** When the key was created */
  createdAt: Date;
  /** Service/component that owns this key */
  owner: string;
}

/**
 * Public key for verification only
 */
export interface PublicKey {
  /** Public key in base64 format */
  publicKey: string;
  /** Key ID for identification */
  keyId: string;
  /** Service/component that owns this key */
  owner: string;
}

/**
 * Result of signature verification
 */
export interface SignatureVerificationResult {
  /** Is the signature valid? */
  valid: boolean;
  /** Key ID that was used for signing */
  keyId?: string;
  /** Signer identity (signedBy field) */
  signer?: string;
  /** Error message if verification failed */
  error?: string;
  /** Verification timestamp */
  verifiedAt: Date;
}

/**
 * Configuration for the signing service
 */
export interface SigningServiceConfig {
  /** Service identifier (used in signedBy field) */
  serviceId: string;
  /** Private key for signing (base64) */
  privateKey?: string;
  /** Key ID */
  keyId?: string;
  /** Known public keys for verification */
  trustedKeys?: PublicKey[];
}

/**
 * Data structure that gets signed
 * (Must be deterministically serializable)
 */
interface SignableEventData {
  eventId: string;
  eventType: string;
  correlationId: string;
  agentId?: string;
  payload: ProofEventPayload;
  previousHash: string | null;
  occurredAt: string;
  signedBy: string;
}

/**
 * Recursively sort object keys for deterministic serialization
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * Create the signable representation of an event
 */
function getSignableData(
  event: Omit<ProofEvent, 'signature' | 'eventHash' | 'recordedAt'>,
  signedBy: string
): SignableEventData {
  return {
    eventId: event.eventId,
    eventType: event.eventType,
    correlationId: event.correlationId,
    agentId: event.agentId,
    payload: event.payload,
    previousHash: event.previousHash,
    occurredAt: event.occurredAt instanceof Date
      ? event.occurredAt.toISOString()
      : event.occurredAt,
    signedBy,
  };
}

/**
 * Serialize data for signing/verification
 */
function serializeForSigning(data: SignableEventData): string {
  const sorted = sortObjectKeys(data);
  return JSON.stringify(sorted);
}

/**
 * Convert ArrayBuffer to base64 string
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate a new Ed25519 signing key pair
 */
export async function generateSigningKeyPair(owner: string): Promise<SigningKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'Ed25519',
    },
    true, // extractable
    ['sign', 'verify']
  ) as { publicKey: Parameters<typeof crypto.subtle.exportKey>[1]; privateKey: Parameters<typeof crypto.subtle.exportKey>[1] };

  const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

  const keyId = `ed25519-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  return {
    publicKey: arrayBufferToBase64(publicKeyBuffer),
    privateKey: arrayBufferToBase64(privateKeyBuffer),
    keyId,
    createdAt: new Date(),
    owner,
  };
}

/**
 * Import a private key from base64 for signing
 */
async function importPrivateKey(privateKeyBase64: string) {
  const keyData = base64ToUint8Array(privateKeyBase64);
  return crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'Ed25519' },
    false,
    ['sign']
  );
}

/**
 * Import a public key from base64 for verification
 */
async function importPublicKey(publicKeyBase64: string) {
  const keyData = base64ToUint8Array(publicKeyBase64);
  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'Ed25519' },
    false,
    ['verify']
  );
}

/**
 * Sign an event using Ed25519
 */
export async function signEvent(
  event: Omit<ProofEvent, 'signature' | 'eventHash' | 'recordedAt'>,
  privateKeyBase64: string,
  signedBy: string
): Promise<string> {
  const signableData = getSignableData(event, signedBy);
  const serialized = serializeForSigning(signableData);
  const encoder = new TextEncoder();
  const data = encoder.encode(serialized);

  const privateKey = await importPrivateKey(privateKeyBase64);
  const signatureBuffer = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    data
  );

  return arrayBufferToBase64(signatureBuffer);
}

/**
 * Verify an event signature using Ed25519
 */
export async function verifyEventSignature(
  event: ProofEvent,
  publicKeyBase64: string
): Promise<SignatureVerificationResult> {
  const verifiedAt = new Date();

  if (!event.signature) {
    return {
      valid: false,
      signer: event.signedBy,
      error: 'Event has no signature',
      verifiedAt,
    };
  }

  if (!event.signedBy) {
    return {
      valid: false,
      error: 'Event has no signedBy field',
      verifiedAt,
    };
  }

  try {
    const signableData = getSignableData(event, event.signedBy);
    const serialized = serializeForSigning(signableData);
    const encoder = new TextEncoder();
    const data = encoder.encode(serialized);

    const publicKey = await importPublicKey(publicKeyBase64);
    const signatureBytes = base64ToUint8Array(event.signature);

    const isValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      signatureBytes,
      data
    );

    return {
      valid: isValid,
      signer: event.signedBy,
      verifiedAt,
      error: isValid ? undefined : 'Signature verification failed',
    };
  } catch (error) {
    return {
      valid: false,
      signer: event.signedBy,
      error: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
      verifiedAt,
    };
  }
}

/**
 * Event Signing Service - Manages signing keys and operations
 */
export class EventSigningService {
  private readonly serviceId: string;
  private readonly privateKey?: string;
  private readonly keyId?: string;
  private readonly trustedKeys: Map<string, PublicKey>;

  constructor(config: SigningServiceConfig) {
    this.serviceId = config.serviceId;
    this.privateKey = config.privateKey;
    this.keyId = config.keyId;
    this.trustedKeys = new Map();

    // Add trusted keys
    for (const key of config.trustedKeys ?? []) {
      this.trustedKeys.set(key.owner, key);
    }
  }

  /**
   * Check if this service can sign events
   */
  canSign(): boolean {
    return this.privateKey !== undefined;
  }

  /**
   * Get the service ID (used in signedBy field)
   */
  getServiceId(): string {
    return this.serviceId;
  }

  /**
   * Get the key ID
   */
  getKeyId(): string | undefined {
    return this.keyId;
  }

  /**
   * Sign an event
   */
  async sign(
    event: Omit<ProofEvent, 'signature' | 'eventHash' | 'recordedAt'>
  ): Promise<string> {
    if (!this.privateKey) {
      throw new Error('Signing service has no private key configured');
    }

    return signEvent(event, this.privateKey, this.serviceId);
  }

  /**
   * Verify an event signature
   */
  async verify(event: ProofEvent): Promise<SignatureVerificationResult> {
    if (!event.signedBy) {
      return {
        valid: false,
        error: 'Event has no signedBy field',
        verifiedAt: new Date(),
      };
    }

    // Find the public key for the signer
    const trustedKey = this.trustedKeys.get(event.signedBy);
    if (!trustedKey) {
      return {
        valid: false,
        signer: event.signedBy,
        error: `No trusted key found for signer: ${event.signedBy}`,
        verifiedAt: new Date(),
      };
    }

    return verifyEventSignature(event, trustedKey.publicKey);
  }

  /**
   * Add a trusted public key
   */
  addTrustedKey(key: PublicKey): void {
    this.trustedKeys.set(key.owner, key);
  }

  /**
   * Remove a trusted public key
   */
  removeTrustedKey(owner: string): boolean {
    return this.trustedKeys.delete(owner);
  }

  /**
   * Get all trusted keys
   */
  getTrustedKeys(): PublicKey[] {
    return Array.from(this.trustedKeys.values());
  }

  /**
   * Check if a signer is trusted
   */
  isTrusted(signer: string): boolean {
    return this.trustedKeys.has(signer);
  }
}

/**
 * Create an event signing service
 */
export function createSigningService(config: SigningServiceConfig): EventSigningService {
  return new EventSigningService(config);
}

/**
 * Batch verification result
 */
export interface BatchVerificationResult {
  /** Number of events verified */
  totalEvents: number;
  /** Number of valid signatures */
  validCount: number;
  /** Number of invalid signatures */
  invalidCount: number;
  /** Number of unsigned events */
  unsignedCount: number;
  /** All verification results */
  results: Array<{
    eventId: string;
    result: SignatureVerificationResult;
  }>;
  /** Overall success (all signed events valid) */
  success: boolean;
}

/**
 * Verify signatures for a batch of events
 */
export async function verifyEventSignatures(
  events: ProofEvent[],
  signingService: EventSigningService
): Promise<BatchVerificationResult> {
  const results: Array<{ eventId: string; result: SignatureVerificationResult }> = [];
  let validCount = 0;
  let invalidCount = 0;
  let unsignedCount = 0;

  for (const event of events) {
    if (!event.signature) {
      unsignedCount++;
      results.push({
        eventId: event.eventId,
        result: {
          valid: false,
          error: 'Event is unsigned',
          verifiedAt: new Date(),
        },
      });
      continue;
    }

    const result = await signingService.verify(event);
    results.push({ eventId: event.eventId, result });

    if (result.valid) {
      validCount++;
    } else {
      invalidCount++;
    }
  }

  return {
    totalEvents: events.length,
    validCount,
    invalidCount,
    unsignedCount,
    results,
    success: invalidCount === 0 && (unsignedCount === 0 || events.length === 0),
  };
}
