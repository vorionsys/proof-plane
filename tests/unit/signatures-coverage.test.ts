/**
 * Event Signatures Coverage Tests
 *
 * Covers untested branches in event-signatures.ts:
 * - EventSigningService.verify with no signedBy, unknown signer
 * - EventSigningService key management: addTrustedKey, removeTrustedKey, getTrustedKeys, isTrusted
 * - verifyEventSignature edge cases: no signature, no signedBy, crypto error
 * - verifyEventSignatures batch function
 * - generateSigningKeyPair
 */

import { describe, it, expect } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  EventSigningService,
  createSigningService,
  generateSigningKeyPair,
  signEvent,
  verifyEventSignature,
  verifyEventSignatures,
} from '../../src/index.js';

function createTestEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: uuidv4(),
    payload: {
      type: 'intent_received',
      intentId: uuidv4(),
      action: 'test',
      actionType: 'read',
      resourceScope: [],
    },
    previousHash: null,
    eventHash: 'deadbeef'.repeat(8),
    occurredAt: new Date(),
    recordedAt: new Date(),
    signedBy: 'test-signer',
    ...overrides,
  };
}

// ── Key Generation ──────────────────────────────────────────────────────────

describe('generateSigningKeyPair', () => {
  it('generates a valid Ed25519 key pair', async () => {
    const keyPair = await generateSigningKeyPair('my-service');

    expect(keyPair.publicKey).toBeTruthy();
    expect(keyPair.privateKey).toBeTruthy();
    expect(keyPair.keyId).toMatch(/^ed25519-/);
    expect(keyPair.owner).toBe('my-service');
    expect(keyPair.createdAt).toBeInstanceOf(Date);
  });

  it('generates unique key pairs each time', async () => {
    const kp1 = await generateSigningKeyPair('svc');
    const kp2 = await generateSigningKeyPair('svc');

    expect(kp1.privateKey).not.toBe(kp2.privateKey);
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
    expect(kp1.keyId).not.toBe(kp2.keyId);
  });
});

// ── Sign + Verify Round Trip ────────────────────────────────────────────────

describe('signEvent + verifyEventSignature', () => {
  it('round-trips successfully', async () => {
    const keyPair = await generateSigningKeyPair('signer');
    const event = createTestEvent({ signedBy: 'signer' });

    const signature = await signEvent(event, keyPair.privateKey, 'signer');
    expect(signature).toBeTruthy();

    const signedEvent = { ...event, signature };
    const result = await verifyEventSignature(signedEvent, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.signer).toBe('signer');
  });

  it('rejects tampered event', async () => {
    const keyPair = await generateSigningKeyPair('signer');
    const event = createTestEvent({ signedBy: 'signer' });

    const signature = await signEvent(event, keyPair.privateKey, 'signer');
    const tamperedEvent = { ...event, signature, agentId: 'tampered-agent' };

    const result = await verifyEventSignature(tamperedEvent, keyPair.publicKey);
    expect(result.valid).toBe(false);
  });
});

// ── verifyEventSignature edge cases ─────────────────────────────────────────

describe('verifyEventSignature — edge cases', () => {
  it('returns invalid for event with no signature', async () => {
    const keyPair = await generateSigningKeyPair('svc');
    const event = createTestEvent({ signature: undefined });

    const result = await verifyEventSignature(event, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('no signature');
  });

  it('returns invalid for event with no signedBy', async () => {
    const keyPair = await generateSigningKeyPair('svc');
    const event = createTestEvent({ signedBy: undefined, signature: 'fakesig' });

    const result = await verifyEventSignature(event, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('no signedBy');
  });

  it('returns invalid with error message for bad key', async () => {
    const event = createTestEvent({ signature: 'badsig' });

    const result = await verifyEventSignature(event, 'not-a-real-key');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Verification error');
  });
});

// ── EventSigningService ─────────────────────────────────────────────────────

describe('EventSigningService', () => {
  it('canSign returns false without private key', () => {
    const svc = createSigningService({ serviceId: 'svc' });
    expect(svc.canSign()).toBe(false);
  });

  it('canSign returns true with private key', async () => {
    const keyPair = await generateSigningKeyPair('svc');
    const svc = createSigningService({ serviceId: 'svc', privateKey: keyPair.privateKey });
    expect(svc.canSign()).toBe(true);
  });

  it('getServiceId returns configured ID', () => {
    const svc = createSigningService({ serviceId: 'my-service' });
    expect(svc.getServiceId()).toBe('my-service');
  });

  it('getKeyId returns configured key ID', () => {
    const svc = createSigningService({ serviceId: 'svc', keyId: 'k1' });
    expect(svc.getKeyId()).toBe('k1');
  });

  it('getKeyId returns undefined when not set', () => {
    const svc = createSigningService({ serviceId: 'svc' });
    expect(svc.getKeyId()).toBeUndefined();
  });

  it('sign throws when no private key', async () => {
    const svc = createSigningService({ serviceId: 'svc' });
    const event = createTestEvent();

    await expect(svc.sign(event)).rejects.toThrow('no private key');
  });

  it('sign and verify round-trip via service', async () => {
    const keyPair = await generateSigningKeyPair('svc');
    const svc = createSigningService({
      serviceId: 'svc',
      privateKey: keyPair.privateKey,
      keyId: keyPair.keyId,
      trustedKeys: [{ publicKey: keyPair.publicKey, keyId: keyPair.keyId, owner: 'svc' }],
    });

    const event = createTestEvent({ signedBy: 'svc' });
    const signature = await svc.sign(event);
    const signedEvent = { ...event, signature, eventHash: 'x'.repeat(64), recordedAt: new Date() };

    const result = await svc.verify(signedEvent);
    expect(result.valid).toBe(true);
  });

  it('verify returns invalid for event with no signedBy', async () => {
    const svc = createSigningService({ serviceId: 'svc' });
    const event = createTestEvent({ signedBy: undefined, signature: 'sig' });

    const result = await svc.verify(event as ProofEvent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('no signedBy');
  });

  it('verify returns invalid for unknown signer', async () => {
    const svc = createSigningService({ serviceId: 'svc' });
    const event = createTestEvent({ signedBy: 'unknown-signer', signature: 'sig' });

    const result = await svc.verify(event);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('No trusted key');
    expect(result.signer).toBe('unknown-signer');
  });

  // ── Key management ──

  it('addTrustedKey adds a new key', () => {
    const svc = createSigningService({ serviceId: 'svc' });
    svc.addTrustedKey({ publicKey: 'pk1', keyId: 'k1', owner: 'alice' });

    expect(svc.isTrusted('alice')).toBe(true);
    expect(svc.getTrustedKeys()).toHaveLength(1);
  });

  it('removeTrustedKey removes existing key', () => {
    const svc = createSigningService({
      serviceId: 'svc',
      trustedKeys: [{ publicKey: 'pk1', keyId: 'k1', owner: 'alice' }],
    });

    expect(svc.isTrusted('alice')).toBe(true);
    expect(svc.removeTrustedKey('alice')).toBe(true);
    expect(svc.isTrusted('alice')).toBe(false);
  });

  it('removeTrustedKey returns false for non-existent key', () => {
    const svc = createSigningService({ serviceId: 'svc' });
    expect(svc.removeTrustedKey('nobody')).toBe(false);
  });

  it('getTrustedKeys returns all keys', () => {
    const svc = createSigningService({
      serviceId: 'svc',
      trustedKeys: [
        { publicKey: 'pk1', keyId: 'k1', owner: 'alice' },
        { publicKey: 'pk2', keyId: 'k2', owner: 'bob' },
      ],
    });

    const keys = svc.getTrustedKeys();
    expect(keys).toHaveLength(2);
    expect(keys.map(k => k.owner).sort()).toEqual(['alice', 'bob']);
  });

  it('isTrusted returns false for unknown signer', () => {
    const svc = createSigningService({ serviceId: 'svc' });
    expect(svc.isTrusted('nobody')).toBe(false);
  });
});

// ── verifyEventSignatures (batch) ───────────────────────────────────────────

describe('verifyEventSignatures (batch)', () => {
  it('handles mix of signed, unsigned, and invalid events', async () => {
    const keyPair = await generateSigningKeyPair('svc');
    const svc = createSigningService({
      serviceId: 'svc',
      privateKey: keyPair.privateKey,
      trustedKeys: [{ publicKey: keyPair.publicKey, keyId: keyPair.keyId, owner: 'svc' }],
    });

    // Signed event
    const event1 = createTestEvent({ signedBy: 'svc' });
    const sig1 = await svc.sign(event1);
    const signedEvent1 = { ...event1, signature: sig1, recordedAt: new Date() } as ProofEvent;

    // Unsigned event
    const unsignedEvent = createTestEvent({ signature: undefined });

    // Event from unknown signer
    const unknownEvent = createTestEvent({ signedBy: 'unknown', signature: 'bad' });

    const result = await verifyEventSignatures(
      [signedEvent1, unsignedEvent, unknownEvent],
      svc,
    );

    expect(result.totalEvents).toBe(3);
    expect(result.validCount).toBe(1);
    expect(result.unsignedCount).toBe(1);
    expect(result.invalidCount).toBe(1);
    expect(result.success).toBe(false); // has invalid and unsigned
  });

  it('returns success=true when all events are signed and valid', async () => {
    const keyPair = await generateSigningKeyPair('svc');
    const svc = createSigningService({
      serviceId: 'svc',
      privateKey: keyPair.privateKey,
      trustedKeys: [{ publicKey: keyPair.publicKey, keyId: keyPair.keyId, owner: 'svc' }],
    });

    const event = createTestEvent({ signedBy: 'svc' });
    const sig = await svc.sign(event);
    const signedEvent = { ...event, signature: sig, recordedAt: new Date() } as ProofEvent;

    const result = await verifyEventSignatures([signedEvent], svc);
    expect(result.success).toBe(true);
    expect(result.validCount).toBe(1);
  });

  it('returns success=true for empty event list', async () => {
    const svc = createSigningService({ serviceId: 'svc' });
    const result = await verifyEventSignatures([], svc);
    expect(result.success).toBe(true);
    expect(result.totalEvents).toBe(0);
  });
});
