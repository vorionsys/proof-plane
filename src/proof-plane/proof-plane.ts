/**
 * Proof Plane - High-level interface for the Vorion audit system
 *
 * The Proof Plane provides a unified API for:
 * - Emitting proof events
 * - Querying the event trail
 * - Verifying chain integrity
 * - Subscribing to events
 * - Hook integration for EVENT_EMITTED notifications
 */

import { v4 as uuidv4 } from 'uuid';
import {
  ProofEventType,
  TrustBand,
  type ProofEvent,
  type ProofEventFilter,
  type ProofEventPayload,
  type Intent,
  type Decision,
  type TrustProfile,
  type IntentReceivedPayload,
  type DecisionMadePayload,
  type TrustDeltaPayload,
  type ExecutionStartedPayload,
  type ExecutionCompletedPayload,
  type ExecutionFailedPayload,
  type ShadowModeStatus,
} from '@vorionsys/contracts';
import {
  type ProofEventStore,
  type EventQueryOptions,
  type EventQueryResult,
  type EventStats,
} from '../events/event-store.js';
import { createInMemoryEventStore } from '../events/memory-store.js';
import {
  type ProofEventEmitter,
  type EmitResult,
  type EventListener,
  createEventEmitter,
} from '../events/event-emitter.js';
import {
  type ChainVerificationResult,
  verifyChainWithDetails,
} from '../events/hash-chain.js';
import {
  type EventSigningService,
  type SignatureVerificationResult,
  type BatchVerificationResult,
  verifyEventSignatures,
} from '../events/event-signatures.js';

/**
 * Hook manager interface for event notifications
 * (Implemented by @vorionsys/a3i HookManager)
 */
export interface EventHookManager {
  executeEventEmitted(context: {
    correlationId: string;
    event: ProofEvent;
  }): Promise<{ aborted: boolean }>;
}

/**
 * Configuration for the Proof Plane
 */
export interface ProofPlaneConfig {
  /** Custom event store (defaults to in-memory) */
  store?: ProofEventStore;
  /** Service identifier for signing events */
  signedBy?: string;
  /** Enable event listeners */
  enableListeners?: boolean;
  /** Hook manager for EVENT_EMITTED notifications */
  hookManager?: EventHookManager;
  /** Enable hooks (default: true if hookManager provided) */
  enableHooks?: boolean;
  /**
   * Shadow mode configuration
   *
   * When enabled, all events are tagged with the specified shadow mode status.
   * This is used for T0_SANDBOX agents whose events need HITL verification
   * before counting toward production trust scores.
   *
   * @default 'production'
   */
  shadowMode?: ShadowModeStatus;
  /**
   * Environment tag for the proof plane instance
   * Helps distinguish production vs testnet events
   */
  environment?: 'production' | 'testnet' | 'development';
  /**
   * Enable Ed25519 digital signatures for events
   *
   * When enabled, all emitted events will be cryptographically signed,
   * providing authenticity and non-repudiation guarantees.
   *
   * SECURITY: Defaults to true — signatures are required for production integrity.
   * Set to false explicitly only for development/testing.
   *
   * @default true
   */
  enableSignatures?: boolean;
  /**
   * Signing service for Ed25519 signatures
   *
   * Required when enableSignatures is true.
   * Can be shared across multiple ProofPlane instances.
   */
  signingService?: EventSigningService;
  /**
   * Private key for signing (base64-encoded Ed25519 private key)
   *
   * Alternative to signingService for simple single-key setups.
   * If both signingService and privateKey are provided, signingService takes precedence.
   */
  privateKey?: string;
}

/**
 * Proof Plane - The Vorion audit trail system
 */
export class ProofPlane {
  private readonly store: ProofEventStore;
  private readonly emitter: ProofEventEmitter;
  private readonly signedBy: string;
  private readonly hookManager?: EventHookManager;
  private readonly enableHooks: boolean;
  private readonly shadowMode: ShadowModeStatus;
  private readonly environment: 'production' | 'testnet' | 'development';
  private readonly signingService?: EventSigningService;
  private readonly enableSignatures: boolean;

  constructor(config: ProofPlaneConfig = {}) {
    this.store = config.store ?? createInMemoryEventStore();

    // Production guard: refuse non-persistent stores in production
    if (
      process.env.NODE_ENV === 'production' &&
      this.store.persistent === false
    ) {
      if (process.env.VORION_ALLOW_MEMORY_STORE === 'true') {
        console.warn(
          '[ProofPlane] WARNING: Using non-persistent event store in production. ' +
          'This is allowed because VORION_ALLOW_MEMORY_STORE=true. ' +
          'Data will be lost on restart.'
        );
      } else {
        throw new Error(
          'FATAL: Cannot use in-memory event store in production. ' +
          'Use a persistent store (PostgreSQL, CockroachDB, etc.) or set ' +
          'VORION_ALLOW_MEMORY_STORE=true to override.'
        );
      }
    }

    this.signedBy = config.signedBy ?? 'orion-proof-plane';
    this.hookManager = config.hookManager;
    this.enableHooks = config.enableHooks ?? (config.hookManager !== undefined);
    this.shadowMode = config.shadowMode ?? 'production';
    this.environment = config.environment ?? 'production';
    this.signingService = config.signingService;

    let signaturesEnabled = config.enableSignatures ?? true;
    if (signaturesEnabled && !config.signingService && !config.privateKey) {
      const envKey = process.env.PROOF_SIGNING_KEY;
      if (envKey) {
        config = { ...config, privateKey: envKey };
      } else {
        console.warn(
          '[ProofPlane] PROOF_SIGNING_KEY not set — event signatures disabled. ' +
          'Set PROOF_SIGNING_KEY or provide a signingService/privateKey to enable signing.'
        );
        signaturesEnabled = false;
      }
    }
    this.enableSignatures = signaturesEnabled;

    this.emitter = createEventEmitter({
      store: this.store,
      signedBy: this.signedBy,
      enableSignatures: this.enableSignatures,
      signingService: this.signingService,
      privateKey: config.privateKey,
      shadowMode: this.shadowMode,
    });

    // Set up hook listener if hooks are enabled
    if (this.enableHooks && this.hookManager) {
      this.setupHookListener();
    }
  }

  /**
   * Set up internal listener for hook notifications
   */
  private setupHookListener(): void {
    this.emitter.addListener((event) => {
      // Fire hook asynchronously (don't block event emission)
      this.fireEventEmittedHook(event).catch((error) => {
        console.error('[ProofPlane] Failed to fire EVENT_EMITTED hook:', error);
      });
    });
  }

  /**
   * Fire the EVENT_EMITTED hook
   */
  private async fireEventEmittedHook(event: ProofEvent): Promise<void> {
    if (!this.hookManager) return;

    await this.hookManager.executeEventEmitted({
      correlationId: event.correlationId,
      event,
    });
  }

  // ============================================================
  // Event Emission - Type-safe helpers for common events
  // ============================================================

  /**
   * Log an intent received event
   */
  async logIntentReceived(
    intent: Intent,
    correlationId?: string
  ): Promise<EmitResult> {
    const payload: IntentReceivedPayload = {
      type: 'intent_received',
      intentId: intent.intentId,
      action: intent.action,
      actionType: intent.actionType,
      resourceScope: intent.resourceScope,
    };

    return this.emitter.emitTyped(
      ProofEventType.INTENT_RECEIVED,
      correlationId ?? intent.correlationId,
      payload,
      intent.agentId
    );
  }

  /**
   * Log an authorization decision event
   */
  async logDecisionMade(
    decision: Decision,
    correlationId?: string
  ): Promise<EmitResult> {
    const payload: DecisionMadePayload = {
      type: 'decision_made',
      decisionId: decision.decisionId,
      intentId: decision.intentId,
      permitted: decision.permitted,
      trustBand: TrustBand[decision.trustBand],
      trustScore: decision.trustScore,
      reasoning: decision.reasoning,
    };

    return this.emitter.emitTyped(
      ProofEventType.DECISION_MADE,
      correlationId ?? decision.correlationId,
      payload,
      decision.agentId
    );
  }

  /**
   * Log a trust score change event
   */
  async logTrustDelta(
    agentId: string,
    previousProfile: TrustProfile,
    newProfile: TrustProfile,
    reason: string,
    correlationId?: string
  ): Promise<EmitResult> {
    const payload: TrustDeltaPayload = {
      type: 'trust_delta',
      deltaId: uuidv4(),
      previousScore: previousProfile.adjustedScore,
      newScore: newProfile.adjustedScore,
      previousBand: TrustBand[previousProfile.band],
      newBand: TrustBand[newProfile.band],
      reason,
    };

    return this.emitter.emitTyped(
      ProofEventType.TRUST_DELTA,
      correlationId ?? uuidv4(),
      payload,
      agentId
    );
  }

  /**
   * Log execution started event
   */
  async logExecutionStarted(
    executionId: string,
    actionId: string,
    decisionId: string,
    adapterId: string,
    agentId: string,
    correlationId: string
  ): Promise<EmitResult> {
    const payload: ExecutionStartedPayload = {
      type: 'execution_started',
      executionId,
      actionId,
      decisionId,
      adapterId,
    };

    return this.emitter.emitTyped(
      ProofEventType.EXECUTION_STARTED,
      correlationId,
      payload,
      agentId
    );
  }

  /**
   * Log execution completed event
   */
  async logExecutionCompleted(
    executionId: string,
    actionId: string,
    durationMs: number,
    outputHash: string,
    agentId: string,
    correlationId: string,
    status: 'success' | 'partial' = 'success'
  ): Promise<EmitResult> {
    const payload: ExecutionCompletedPayload = {
      type: 'execution_completed',
      executionId,
      actionId,
      status,
      durationMs,
      outputHash,
    };

    return this.emitter.emitTyped(
      ProofEventType.EXECUTION_COMPLETED,
      correlationId,
      payload,
      agentId
    );
  }

  /**
   * Log execution failed event
   */
  async logExecutionFailed(
    executionId: string,
    actionId: string,
    error: string,
    durationMs: number,
    retryable: boolean,
    agentId: string,
    correlationId: string
  ): Promise<EmitResult> {
    const payload: ExecutionFailedPayload = {
      type: 'execution_failed',
      executionId,
      actionId,
      error,
      durationMs,
      retryable,
    };

    return this.emitter.emitTyped(
      ProofEventType.EXECUTION_FAILED,
      correlationId,
      payload,
      agentId
    );
  }

  /**
   * Log a generic proof event
   */
  async logEvent(
    eventType: ProofEventType,
    correlationId: string,
    payload: ProofEventPayload,
    agentId?: string
  ): Promise<EmitResult> {
    return this.emitter.emitTyped(eventType, correlationId, payload, agentId);
  }

  // ============================================================
  // Event Queries
  // ============================================================

  /**
   * Get an event by ID
   */
  async getEvent(eventId: string): Promise<ProofEvent | null> {
    return this.store.get(eventId);
  }

  /**
   * Get the latest event
   */
  async getLatestEvent(): Promise<ProofEvent | null> {
    return this.store.getLatest();
  }

  /**
   * Query events with filters
   */
  async queryEvents(
    filter?: ProofEventFilter,
    options?: EventQueryOptions
  ): Promise<EventQueryResult> {
    return this.store.query(filter, options);
  }

  /**
   * Get all events for a correlation ID (trace a request)
   */
  async getTrace(correlationId: string): Promise<ProofEvent[]> {
    return this.store.getByCorrelationId(correlationId, { order: 'asc' });
  }

  /**
   * Get all events for an agent
   */
  async getAgentHistory(agentId: string, options?: EventQueryOptions): Promise<ProofEvent[]> {
    return this.store.getByAgentId(agentId, options);
  }

  /**
   * Get events by type
   */
  async getEventsByType(
    eventType: ProofEventType,
    options?: EventQueryOptions
  ): Promise<ProofEvent[]> {
    return this.store.getByType(eventType, options);
  }

  /**
   * Get event statistics
   */
  async getStats(): Promise<EventStats> {
    return this.store.getStats();
  }

  /**
   * Get event count
   */
  async getEventCount(filter?: ProofEventFilter): Promise<number> {
    return this.store.count(filter);
  }

  // ============================================================
  // Chain Verification
  // ============================================================

  /**
   * Verify the entire event chain
   */
  async verifyChain(fromEventId?: string, limit?: number): Promise<ChainVerificationResult> {
    const events = await this.store.getChain(fromEventId, limit);
    return verifyChainWithDetails(events);
  }

  /**
   * Verify chain integrity for a specific correlation ID
   */
  async verifyCorrelationChain(correlationId: string): Promise<ChainVerificationResult> {
    const events = await this.store.getByCorrelationId(correlationId, { order: 'asc' });
    return verifyChainWithDetails(events);
  }

  // ============================================================
  // Signature Verification
  // ============================================================

  /**
   * Check if signature verification is available
   */
  isSignatureVerificationEnabled(): boolean {
    return this.signingService !== undefined;
  }

  /**
   * Check if this proof plane is configured for signing
   */
  isSigningEnabled(): boolean {
    return this.enableSignatures && this.emitter.isSigningEnabled();
  }

  /**
   * Get the signing service (if configured)
   */
  getSigningService(): EventSigningService | undefined {
    return this.signingService;
  }

  /**
   * Verify signature on a single event
   *
   * Requires a signing service with trusted keys configured.
   */
  async verifyEventSignature(event: ProofEvent): Promise<SignatureVerificationResult> {
    if (!this.signingService) {
      return {
        valid: false,
        error: 'No signing service configured for verification',
        verifiedAt: new Date(),
      };
    }

    return this.signingService.verify(event);
  }

  /**
   * Verify signatures for multiple events
   *
   * Returns detailed results for each event.
   */
  async verifySignatures(events: ProofEvent[]): Promise<BatchVerificationResult> {
    if (!this.signingService) {
      return {
        totalEvents: events.length,
        validCount: 0,
        invalidCount: 0,
        unsignedCount: events.length,
        results: events.map(e => ({
          eventId: e.eventId,
          result: {
            valid: false,
            error: 'No signing service configured for verification',
            verifiedAt: new Date(),
          },
        })),
        success: false,
      };
    }

    return verifyEventSignatures(events, this.signingService);
  }

  /**
   * Verify signatures for all events in a correlation chain
   */
  async verifyCorrelationSignatures(correlationId: string): Promise<BatchVerificationResult> {
    const events = await this.store.getByCorrelationId(correlationId, { order: 'asc' });
    return this.verifySignatures(events);
  }

  /**
   * Verify both chain integrity AND signatures
   *
   * Returns combined verification results.
   */
  async verifyChainAndSignatures(
    fromEventId?: string,
    limit?: number
  ): Promise<{
    chain: ChainVerificationResult;
    signatures: BatchVerificationResult;
    fullyVerified: boolean;
  }> {
    const events = await this.store.getChain(fromEventId, limit);
    const chain = await verifyChainWithDetails(events);
    const signatures = await this.verifySignatures(events);

    return {
      chain,
      signatures,
      fullyVerified: chain.valid && signatures.success,
    };
  }

  // ============================================================
  // Subscriptions
  // ============================================================

  /**
   * Subscribe to new events
   */
  subscribe(listener: EventListener): () => void {
    this.emitter.addListener(listener);
    return () => this.emitter.removeListener(listener);
  }

  /**
   * Subscribe to events of a specific type
   */
  subscribeToType(eventType: ProofEventType, listener: EventListener): () => void {
    const filteredListener: EventListener = (event) => {
      if (event.eventType === eventType) {
        return listener(event);
      }
    };
    this.emitter.addListener(filteredListener);
    return () => this.emitter.removeListener(filteredListener);
  }

  // ============================================================
  // Utilities
  // ============================================================

  /**
   * Get the underlying event store
   */
  getStore(): ProofEventStore {
    return this.store;
  }

  /**
   * Get the event emitter
   */
  getEmitter(): ProofEventEmitter {
    return this.emitter;
  }

  /**
   * Get the hook manager
   */
  getHookManager(): EventHookManager | undefined {
    return this.hookManager;
  }

  /**
   * Check if hooks are enabled
   */
  isHooksEnabled(): boolean {
    return this.enableHooks;
  }

  // ============================================================
  // Shadow Mode (T0 Sandbox Support)
  // ============================================================

  /**
   * Check if this proof plane is in shadow mode
   */
  isShadowMode(): boolean {
    return this.shadowMode !== 'production';
  }

  /**
   * Get the current shadow mode status
   */
  getShadowMode(): ShadowModeStatus {
    return this.shadowMode;
  }

  /**
   * Get the environment tag
   */
  getEnvironment(): string {
    return this.environment;
  }

  /**
   * Query shadow/testnet events that need HITL verification
   */
  async getUnverifiedShadowEvents(
    agentId?: string,
    options?: EventQueryOptions
  ): Promise<ProofEvent[]> {
    const result = await this.store.query(
      { agentId },
      { ...options, shadowModeOnly: ['shadow', 'testnet'] }
    );
    return result.events;
  }

  /**
   * Mark a shadow event as verified by HITL
   * Note: This creates a new verification event, not modifying the original
   */
  async verifyShadowEvent(
    eventId: string,
    verificationId: string,
    verifiedBy: string,
    approved: boolean
  ): Promise<EmitResult> {
    const event = await this.store.get(eventId);
    if (!event) {
      throw new Error(`Event ${eventId} not found`);
    }

    if (event.shadowMode !== 'shadow' && event.shadowMode !== 'testnet') {
      throw new Error(`Event ${eventId} is not a shadow event (status: ${event.shadowMode ?? 'production'})`);
    }

    // Log verification as a new event
    return this.logEvent(
      ProofEventType.COMPONENT_UPDATED,
      event.correlationId,
      {
        type: 'shadow_verification',
        eventId,
        verificationId,
        verifiedBy,
        approved,
        newStatus: approved ? 'verified' : 'rejected',
        previousStatus: event.shadowMode,
      },
      event.agentId
    );
  }

  /**
   * Clear all events (for testing only)
   */
  async clear(): Promise<void> {
    await this.store.clear();
  }
}

/**
 * Create a Proof Plane instance
 */
export function createProofPlane(config?: ProofPlaneConfig): ProofPlane {
  return new ProofPlane(config);
}
