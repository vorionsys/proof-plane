/**
 * ProofPlane Coverage Tests — shadow mode, signature verification, utilities
 *
 * Covers untested methods in proof-plane.ts:
 * - Shadow mode: isShadowMode, getShadowMode, getUnverifiedShadowEvents, verifyShadowEvent
 * - Signatures: verifyEventSignature, verifySignatures, verifyCorrelationSignatures, verifyChainAndSignatures
 * - Utilities: getStore, getEmitter, getEnvironment, isSigningEnabled, getSigningService
 * - clear()
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import {
  ProofEventType,
  TrustBand,
  ActionType,
  DataSensitivity,
  Reversibility,
  type Intent,
} from '@vorionsys/contracts';
import {
  ProofPlane,
  createProofPlane,
  EventSigningService,
  generateSigningKeyPair,
} from '../../src/index.js';

function createIntent(overrides: Partial<Intent> = {}): Intent {
  return {
    intentId: uuidv4(),
    agentId: uuidv4(),
    correlationId: uuidv4(),
    action: 'read-file',
    actionType: ActionType.READ,
    resourceScope: ['/data/test.txt'],
    dataSensitivity: DataSensitivity.INTERNAL,
    reversibility: Reversibility.REVERSIBLE,
    justification: 'Test',
    createdAt: new Date(),
    ...overrides,
  };
}

// ── Shadow Mode ──────────────────────────────────────────────────────────────

describe('ProofPlane — shadow mode', () => {
  it('isShadowMode returns false for production', () => {
    const pp = createProofPlane({ enableSignatures: false });
    expect(pp.isShadowMode()).toBe(false);
    expect(pp.getShadowMode()).toBe('production');
  });

  it('isShadowMode returns true for shadow', () => {
    const pp = createProofPlane({ shadowMode: 'shadow', enableSignatures: false });
    expect(pp.isShadowMode()).toBe(true);
    expect(pp.getShadowMode()).toBe('shadow');
  });

  it('isShadowMode returns true for testnet', () => {
    const pp = createProofPlane({ shadowMode: 'testnet', enableSignatures: false });
    expect(pp.isShadowMode()).toBe(true);
    expect(pp.getShadowMode()).toBe('testnet');
  });

  it('getUnverifiedShadowEvents returns shadow events', async () => {
    const pp = createProofPlane({ shadowMode: 'shadow', enableSignatures: false });
    await pp.logIntentReceived(createIntent());
    await pp.logIntentReceived(createIntent());

    const events = await pp.getUnverifiedShadowEvents();
    expect(events).toHaveLength(2);
    expect(events[0].shadowMode).toBe('shadow');
  });

  it('getUnverifiedShadowEvents filters by agentId', async () => {
    const agentId = uuidv4();
    const pp = createProofPlane({ shadowMode: 'shadow', enableSignatures: false });
    await pp.logIntentReceived(createIntent({ agentId }));
    await pp.logIntentReceived(createIntent()); // different agent

    const events = await pp.getUnverifiedShadowEvents(agentId);
    expect(events).toHaveLength(1);
    expect(events[0].agentId).toBe(agentId);
  });

  it('verifyShadowEvent emits verification event for shadow event', async () => {
    const pp = createProofPlane({ shadowMode: 'shadow', enableSignatures: false });
    const result = await pp.logIntentReceived(createIntent());

    const verificationResult = await pp.verifyShadowEvent(
      result.event.eventId,
      uuidv4(),
      'reviewer-1',
      true,
    );

    expect(verificationResult.event.eventType).toBe(ProofEventType.COMPONENT_UPDATED);
    const payload = verificationResult.event.payload as Record<string, unknown>;
    expect(payload.type).toBe('shadow_verification');
    expect(payload.approved).toBe(true);
    expect(payload.newStatus).toBe('verified');
  });

  it('verifyShadowEvent rejects non-existent event', async () => {
    const pp = createProofPlane({ enableSignatures: false });

    await expect(pp.verifyShadowEvent(uuidv4(), uuidv4(), 'r', true))
      .rejects.toThrow('not found');
  });

  it('verifyShadowEvent rejects non-shadow event', async () => {
    const pp = createProofPlane({ enableSignatures: false }); // production mode
    const result = await pp.logIntentReceived(createIntent());

    await expect(pp.verifyShadowEvent(result.event.eventId, uuidv4(), 'r', true))
      .rejects.toThrow('not a shadow event');
  });

  it('verifyShadowEvent with rejected=false sets status to rejected', async () => {
    const pp = createProofPlane({ shadowMode: 'testnet', enableSignatures: false });
    const result = await pp.logIntentReceived(createIntent());

    const verResult = await pp.verifyShadowEvent(
      result.event.eventId,
      uuidv4(),
      'reviewer-2',
      false,
    );

    const payload = verResult.event.payload as Record<string, unknown>;
    expect(payload.newStatus).toBe('rejected');
    expect(payload.previousStatus).toBe('testnet');
  });
});

// ── Signature Verification (without real keys) ──────────────────────────────

describe('ProofPlane — signature verification (no signing service)', () => {
  let pp: ProofPlane;

  beforeEach(() => {
    pp = createProofPlane({ enableSignatures: false });
  });

  it('isSignatureVerificationEnabled returns false without signing service', () => {
    expect(pp.isSignatureVerificationEnabled()).toBe(false);
  });

  it('isSigningEnabled returns false without keys', () => {
    expect(pp.isSigningEnabled()).toBe(false);
  });

  it('getSigningService returns undefined', () => {
    expect(pp.getSigningService()).toBeUndefined();
  });

  it('verifyEventSignature returns invalid when no service', async () => {
    const result = await pp.logIntentReceived(createIntent());
    const verification = await pp.verifyEventSignature(result.event);

    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('No signing service');
  });

  it('verifySignatures returns all unsigned when no service', async () => {
    await pp.logIntentReceived(createIntent());
    await pp.logIntentReceived(createIntent());
    const chain = await pp.getStore().getChain();

    const batch = await pp.verifySignatures(chain);
    expect(batch.totalEvents).toBe(2);
    expect(batch.unsignedCount).toBe(2);
    expect(batch.validCount).toBe(0);
    expect(batch.success).toBe(false);
    expect(batch.results).toHaveLength(2);
  });

  it('verifyCorrelationSignatures returns results for correlation', async () => {
    const correlationId = uuidv4();
    await pp.logIntentReceived(createIntent({ correlationId }));

    const batch = await pp.verifyCorrelationSignatures(correlationId);
    expect(batch.totalEvents).toBe(1);
    expect(batch.unsignedCount).toBe(1);
  });

  it('verifyChainAndSignatures returns combined results', async () => {
    await pp.logIntentReceived(createIntent());
    await pp.logIntentReceived(createIntent());

    const combined = await pp.verifyChainAndSignatures();
    expect(combined.chain.valid).toBe(true);
    expect(combined.chain.totalEvents).toBe(2);
    expect(combined.signatures.totalEvents).toBe(2);
    expect(combined.fullyVerified).toBe(false); // no signatures
  });

  it('verifyCorrelationChain verifies events by correlationId', async () => {
    const correlationId = uuidv4();
    await pp.logIntentReceived(createIntent({ correlationId }));
    await pp.logEvent(
      ProofEventType.DECISION_MADE,
      correlationId,
      { type: 'decision_made', decisionId: uuidv4(), intentId: uuidv4(), permitted: true, trustBand: 'T2', trustScore: 50, reasoning: ['ok'] },
    );

    const result = await pp.verifyCorrelationChain(correlationId);
    expect(result.valid).toBe(true);
    expect(result.totalEvents).toBe(2);
  });
});

// ── Signature Verification (with real keys) ─────────────────────────────────

describe('ProofPlane — signature verification (with signing service)', () => {
  it('signs and verifies events with Ed25519', async () => {
    const keyPair = await generateSigningKeyPair('test-service');
    const signingService = new EventSigningService({
      serviceId: 'test-service',
      privateKey: keyPair.privateKey,
      keyId: keyPair.keyId,
      trustedKeys: [{ publicKey: keyPair.publicKey, keyId: keyPair.keyId, owner: 'test-service' }],
    });

    const pp = createProofPlane({
      signedBy: 'test-service',
      enableSignatures: true,
      signingService,
    });

    expect(pp.isSignatureVerificationEnabled()).toBe(true);
    expect(pp.isSigningEnabled()).toBe(true);
    expect(pp.getSigningService()).toBe(signingService);

    const result = await pp.logIntentReceived(createIntent());
    expect(result.event.signature).toBeTruthy();

    const verification = await pp.verifyEventSignature(result.event);
    expect(verification.valid).toBe(true);
  });

  it('verifyChainAndSignatures returns fullyVerified=true with valid sigs', async () => {
    const keyPair = await generateSigningKeyPair('signer');
    const signingService = new EventSigningService({
      serviceId: 'signer',
      privateKey: keyPair.privateKey,
      keyId: keyPair.keyId,
      trustedKeys: [{ publicKey: keyPair.publicKey, keyId: keyPair.keyId, owner: 'signer' }],
    });

    const pp = createProofPlane({
      signedBy: 'signer',
      enableSignatures: true,
      signingService,
    });

    await pp.logIntentReceived(createIntent());
    await pp.logIntentReceived(createIntent());

    const combined = await pp.verifyChainAndSignatures();
    expect(combined.chain.valid).toBe(true);
    expect(combined.signatures.success).toBe(true);
    expect(combined.fullyVerified).toBe(true);
  });
});

// ── Utilities ────────────────────────────────────────────────────────────────

describe('ProofPlane — utilities', () => {
  it('getStore returns the underlying store', () => {
    const pp = createProofPlane({ enableSignatures: false });
    expect(pp.getStore()).toBeDefined();
  });

  it('getEmitter returns the event emitter', () => {
    const pp = createProofPlane({ enableSignatures: false });
    expect(pp.getEmitter()).toBeDefined();
  });

  it('getEnvironment returns configured environment', () => {
    const pp = createProofPlane({ environment: 'testnet', enableSignatures: false });
    expect(pp.getEnvironment()).toBe('testnet');
  });

  it('getEnvironment defaults to production', () => {
    const pp = createProofPlane({ enableSignatures: false });
    expect(pp.getEnvironment()).toBe('production');
  });

  it('getEventsByType returns filtered events', async () => {
    const pp = createProofPlane({ enableSignatures: false });
    await pp.logIntentReceived(createIntent());
    await pp.logEvent(ProofEventType.DECISION_MADE, uuidv4(), {
      type: 'decision_made', decisionId: uuidv4(), intentId: uuidv4(),
      permitted: true, trustBand: 'T2', trustScore: 50, reasoning: ['ok'],
    });

    const intents = await pp.getEventsByType(ProofEventType.INTENT_RECEIVED);
    expect(intents).toHaveLength(1);
  });

  it('getEventCount with filter', async () => {
    const agentId = uuidv4();
    const pp = createProofPlane({ enableSignatures: false });
    await pp.logIntentReceived(createIntent({ agentId }));
    await pp.logIntentReceived(createIntent());

    const count = await pp.getEventCount({ agentId });
    expect(count).toBe(1);
  });

  it('clear removes all events', async () => {
    const pp = createProofPlane({ enableSignatures: false });
    await pp.logIntentReceived(createIntent());
    await pp.logIntentReceived(createIntent());
    expect(await pp.getEventCount()).toBe(2);

    await pp.clear();
    expect(await pp.getEventCount()).toBe(0);
  });
});
