/**
 * Signature Enforcement Tests for ProofEventEmitter
 *
 * Validates that Ed25519 signature enforcement works correctly:
 * - Production mode rejects missing signing keys when signatures are enabled
 * - Production mode rejects events when signing fails
 * - Development mode allows unsigned events with warnings
 * - Unsigned events are properly flagged in batch verification
 */

import { describe, it, expect, afterEach } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType } from '@vorionsys/contracts';
import { ProofEventEmitter, createEventEmitter } from '../src/events/event-emitter.js';
import { createInMemoryEventStore } from '../src/events/memory-store.js';
import {
  EventSigningService,
  generateSigningKeyPair,
  verifyEventSignatures,
} from '../src/events/event-signatures.js';
import { createProofPlane } from '../src/index.js';

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Signature Enforcement - ProofEventEmitter', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
  });

  // ── Production mode: constructor rejects missing keys ──────────────────

  describe('production mode enforcement', () => {
    it('throws when signatures enabled but no keys in production', () => {
      process.env.NODE_ENV = 'production';

      expect(() =>
        createEventEmitter({
          store: createInMemoryEventStore(),
          enableSignatures: true,
          signedBy: 'test-service',
        })
      ).toThrow('Signatures enabled but no signingService or privateKey provided in production');
    });

    it('succeeds in production when signing keys are provided', async () => {
      process.env.NODE_ENV = 'production';
      const keyPair = await generateSigningKeyPair('test-service');

      expect(() =>
        createEventEmitter({
          store: createInMemoryEventStore(),
          enableSignatures: true,
          privateKey: keyPair.privateKey,
          signedBy: 'test-service',
        })
      ).not.toThrow();
    });

    it('succeeds in production when signingService is provided', async () => {
      process.env.NODE_ENV = 'production';
      const keyPair = await generateSigningKeyPair('test-service');
      const signingService = new EventSigningService({
        serviceId: 'test-service',
        privateKey: keyPair.privateKey,
        keyId: keyPair.keyId,
      });

      expect(() =>
        createEventEmitter({
          store: createInMemoryEventStore(),
          enableSignatures: true,
          signingService,
          signedBy: 'test-service',
        })
      ).not.toThrow();
    });

    it('succeeds in production when signatures are not enabled', () => {
      process.env.NODE_ENV = 'production';

      expect(() =>
        createEventEmitter({
          store: createInMemoryEventStore(),
          enableSignatures: false,
          signedBy: 'test-service',
        })
      ).not.toThrow();
    });
  });

  // ── Development mode: unsigned events allowed ──────────────────────────

  describe('development mode (non-production)', () => {
    it('allows construction without signing keys in development', () => {
      process.env.NODE_ENV = 'development';

      expect(() =>
        createEventEmitter({
          store: createInMemoryEventStore(),
          enableSignatures: true,
          signedBy: 'test-service',
        })
      ).not.toThrow();
    });

    it('allows construction without signing keys in test', () => {
      process.env.NODE_ENV = 'test';

      expect(() =>
        createEventEmitter({
          store: createInMemoryEventStore(),
          enableSignatures: true,
          signedBy: 'test-service',
        })
      ).not.toThrow();
    });

    it('emits events without signature in development', async () => {
      process.env.NODE_ENV = 'development';

      const emitter = createEventEmitter({
        store: createInMemoryEventStore(),
        enableSignatures: false,
        signedBy: 'test-service',
      });

      const result = await emitter.emitTyped(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: ['/test'],
        }
      );

      expect(result.event).toBeDefined();
      expect(result.event.signature).toBeUndefined();
    });
  });

  // ── Unsigned events flagged in verification ────────────────────────────

  describe('unsigned events flagged in batch verification', () => {
    it('batch verification flags unsigned events', async () => {
      process.env.NODE_ENV = 'test';
      const keyPair = await generateSigningKeyPair('test-verifier');

      const signingService = new EventSigningService({
        serviceId: 'test-verifier',
        privateKey: keyPair.privateKey,
        keyId: keyPair.keyId,
        trustedKeys: [{
          publicKey: keyPair.publicKey,
          keyId: keyPair.keyId,
          owner: 'test-verifier',
        }],
      });

      // Create events without signatures
      const emitter = createEventEmitter({
        store: createInMemoryEventStore(),
        enableSignatures: false,
        signedBy: 'test-verifier',
      });

      const result = await emitter.emitTyped(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: ['/test'],
        }
      );

      // Verify the unsigned event
      const batchResult = await verifyEventSignatures([result.event], signingService);
      expect(batchResult.success).toBe(false);
      expect(batchResult.unsignedCount).toBe(1);
      expect(batchResult.validCount).toBe(0);
    });

    it('batch verification succeeds for signed events', async () => {
      process.env.NODE_ENV = 'test';
      const keyPair = await generateSigningKeyPair('test-signer');

      const signingService = new EventSigningService({
        serviceId: 'test-signer',
        privateKey: keyPair.privateKey,
        keyId: keyPair.keyId,
        trustedKeys: [{
          publicKey: keyPair.publicKey,
          keyId: keyPair.keyId,
          owner: 'test-signer',
        }],
      });

      const emitter = createEventEmitter({
        store: createInMemoryEventStore(),
        enableSignatures: true,
        signingService,
        signedBy: 'test-signer',
      });

      const result = await emitter.emitTyped(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: ['/test'],
        }
      );

      expect(result.event.signature).toBeTruthy();

      const batchResult = await verifyEventSignatures([result.event], signingService);
      expect(batchResult.success).toBe(true);
      expect(batchResult.validCount).toBe(1);
      expect(batchResult.unsignedCount).toBe(0);
    });
  });

  // ── ProofPlane-level verification ──────────────────────────────────────

  describe('ProofPlane signature verification', () => {
    it('verifySignatures returns failure for unsigned events', async () => {
      process.env.NODE_ENV = 'test';

      const pp = createProofPlane({ signedBy: 'unsigned-test' });

      await pp.logEvent(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: ['/test'],
        }
      );

      const events = (await pp.queryEvents()).events;
      const result = await pp.verifySignatures(events);

      // No signing service configured, so all events fail
      expect(result.success).toBe(false);
      expect(result.unsignedCount).toBe(events.length);
    });

    it('verifyChainAndSignatures reports unsigned events', async () => {
      process.env.NODE_ENV = 'test';

      const pp = createProofPlane({ signedBy: 'chain-sig-test' });

      await pp.logEvent(
        ProofEventType.INTENT_RECEIVED,
        uuidv4(),
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: ['/test'],
        }
      );

      const result = await pp.verifyChainAndSignatures();

      // Chain integrity should pass, but signatures should fail
      expect(result.chain.valid).toBe(true);
      expect(result.signatures.success).toBe(false);
      expect(result.fullyVerified).toBe(false);
    });

    it('isSigningEnabled returns false without signing config', () => {
      process.env.NODE_ENV = 'test';
      const pp = createProofPlane({ signedBy: 'no-keys' });
      expect(pp.isSigningEnabled()).toBe(false);
    });
  });
});
