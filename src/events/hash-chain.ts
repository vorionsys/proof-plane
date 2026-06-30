/**
 * Hash Chain Utilities - Cryptographic hash chain for tamper detection
 *
 * Each proof event contains a hash of its contents and a reference
 * to the previous event's hash, forming an immutable chain.
 *
 * Dual-hash: SHA-256 (primary chain) + SHA3-256 (integrity anchor).
 */

import * as nodeCrypto from 'node:crypto';
import type { ProofEvent, ProofEventPayload } from '@vorionsys/contracts';

/**
 * Create a SHA-256 hash of the given data
 */
export async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create a SHA3-256 hash of the given data (integrity anchor)
 */
export function sha3_256(data: string): string {
  return nodeCrypto.createHash('sha3-256').update(data).digest('hex');
}

/**
 * Data structure used for hashing an event
 * (excludes eventHash itself and recorded metadata)
 */
interface HashableEventData {
  eventId: string;
  eventType: string;
  correlationId: string;
  agentId?: string;
  payload: ProofEventPayload;
  previousHash: string | null;
  occurredAt: string;
  signedBy?: string;
  signature?: string;
}

/**
 * Create the hashable representation of an event
 */
function getHashableData(event: Omit<ProofEvent, 'eventHash' | 'recordedAt'>): HashableEventData {
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
    signedBy: event.signedBy,
    signature: event.signature,
  };
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
 * Compute the hash of an event's content
 */
export async function computeEventHash(
  event: Omit<ProofEvent, 'eventHash' | 'recordedAt'>
): Promise<string> {
  const hashable = getHashableData(event);
  const sortedHashable = sortObjectKeys(hashable);
  const serialized = JSON.stringify(sortedHashable);
  return sha256(serialized);
}

/**
 * Compute the SHA3-256 integrity anchor hash for an event
 */
export function computeEventHash3(
  event: Omit<ProofEvent, 'eventHash' | 'eventHash3' | 'recordedAt'>
): string {
  const hashable = getHashableData(event);
  const sortedHashable = sortObjectKeys(hashable);
  const serialized = JSON.stringify(sortedHashable);
  return sha3_256(serialized);
}

/**
 * Verify that an event's SHA-256 hash is correct
 */
export async function verifyEventHash(event: ProofEvent): Promise<boolean> {
  const computedHash = await computeEventHash(event);
  return computedHash === event.eventHash;
}

/**
 * Verify that an event's SHA3-256 integrity hash is correct (if present)
 * Returns true if hash3 is absent (pre-upgrade record).
 */
export function verifyEventHash3(event: ProofEvent): boolean {
  if (!event.eventHash3) return true; // Pre-upgrade records don't have hash3
  const computedHash3 = computeEventHash3(event);
  return computedHash3 === event.eventHash3;
}

/**
 * Verify that an event correctly chains to the previous event
 */
export function verifyChainLink(event: ProofEvent, previousEvent: ProofEvent | null): boolean {
  if (previousEvent === null) {
    // First event in chain should have null previousHash
    return event.previousHash === null;
  }
  return event.previousHash === previousEvent.eventHash;
}

/**
 * Verify an entire chain of events
 */
export async function verifyChain(events: ProofEvent[]): Promise<{
  valid: boolean;
  verifiedCount: number;
  brokenAtIndex?: number;
  brokenAtEventId?: string;
  error?: string;
}> {
  if (events.length === 0) {
    return { valid: true, verifiedCount: 0 };
  }

  // Events should be in order (oldest first)
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const previousEvent = i === 0 ? null : events[i - 1];

    // Verify SHA-256 hash integrity
    const hashValid = await verifyEventHash(event);
    if (!hashValid) {
      return {
        valid: false,
        verifiedCount: i,
        brokenAtIndex: i,
        brokenAtEventId: event.eventId,
        error: `Event ${event.eventId} has invalid SHA-256 hash`,
      };
    }

    // Verify SHA3-256 integrity anchor (if present)
    const hash3Valid = verifyEventHash3(event);
    if (!hash3Valid) {
      return {
        valid: false,
        verifiedCount: i,
        brokenAtIndex: i,
        brokenAtEventId: event.eventId,
        error: `Event ${event.eventId} has invalid SHA3-256 hash`,
      };
    }

    // Verify chain link
    const chainValid = verifyChainLink(event, previousEvent);
    if (!chainValid) {
      return {
        valid: false,
        verifiedCount: i,
        brokenAtIndex: i,
        brokenAtEventId: event.eventId,
        error: `Event ${event.eventId} has broken chain link`,
      };
    }
  }

  return { valid: true, verifiedCount: events.length };
}

/**
 * Create a genesis hash for the first event in a chain
 */
export function getGenesisHash(): null {
  return null;
}

/**
 * Result of chain verification with detailed info
 */
export interface ChainVerificationResult {
  /** Is the chain valid? */
  valid: boolean;
  /** Number of events successfully verified */
  verifiedCount: number;
  /** Total events in chain */
  totalEvents: number;
  /** First event ID in chain */
  firstEventId?: string;
  /** Last event ID in chain */
  lastEventId?: string;
  /** Event ID where chain broke (if invalid) */
  brokenAtEventId?: string;
  /** Index where chain broke */
  brokenAtIndex?: number;
  /** Error description */
  error?: string;
}

/**
 * Verify a chain and return detailed results
 */
export async function verifyChainWithDetails(events: ProofEvent[]): Promise<ChainVerificationResult> {
  const result = await verifyChain(events);

  return {
    valid: result.valid,
    verifiedCount: result.verifiedCount,
    totalEvents: events.length,
    firstEventId: events[0]?.eventId,
    lastEventId: events[events.length - 1]?.eventId,
    brokenAtEventId: result.brokenAtEventId,
    brokenAtIndex: result.brokenAtIndex,
    error: result.error,
  };
}
