/**
 * Event Emitter - Creates and chains proof events
 *
 * Handles the creation of properly hashed and chained proof events,
 * ensuring immutability and tamper detection.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  ProofEvent,
  ProofEventPayload,
  ProofEventType,
  LogProofEventRequest,
  ShadowModeStatus,
} from '@vorionsys/contracts';
import { type ProofEventStore, EventStoreError, EventStoreErrorCode } from './event-store.js';
import { computeEventHash, computeEventHash3, getGenesisHash } from './hash-chain.js';
import { type EventSigningService, signEvent } from './event-signatures.js';

/**
 * Configuration for the event emitter
 */
export interface EventEmitterConfig {
  /** Event store to use */
  store: ProofEventStore;
  /** Signer identifier (e.g., service name) */
  signedBy?: string;
  /** Enable signature generation */
  enableSignatures?: boolean;
  /**
   * Signing service for Ed25519 signatures
   * Required when enableSignatures is true
   */
  signingService?: EventSigningService;
  /**
   * Private key for signing (base64-encoded Ed25519 private key)
   * Alternative to signingService for simple setups
   */
  privateKey?: string;
  /** Event listeners for real-time notifications */
  listeners?: EventListener[];
  /**
   * Shadow mode for sandbox/testnet events
   *
   * When set, all emitted events are tagged with this status.
   * Used for T0_SANDBOX agents whose events need HITL verification.
   *
   * @default 'production'
   */
  shadowMode?: ShadowModeStatus;
}

/**
 * Event listener callback
 */
export type EventListener = (event: ProofEvent) => void | Promise<void>;

/**
 * Result of emitting an event
 */
export interface EmitResult {
  /** The created event */
  event: ProofEvent;
  /** Whether this is the first event in the chain */
  isGenesis: boolean;
  /** Previous event hash (null for genesis) */
  previousHash: string | null;
}

/**
 * Batch emit options
 */
export interface BatchEmitOptions {
  /** Whether to stop on first error */
  stopOnError?: boolean;
  /** Correlation ID to use for all events */
  correlationId?: string;
}

/**
 * Result of batch emit
 */
export interface BatchEmitResult {
  /** Successfully created events */
  events: ProofEvent[];
  /** Errors encountered */
  errors: Array<{ index: number; error: Error }>;
  /** Whether all events were created successfully */
  success: boolean;
}

/**
 * ProofEventEmitter - Creates properly hashed and chained events
 */
export class ProofEventEmitter {
  private readonly store: ProofEventStore;
  private readonly signedBy?: string;
  private readonly enableSignatures: boolean;
  private readonly signingService?: EventSigningService;
  private readonly privateKey?: string;
  private readonly listeners: EventListener[];
  private readonly shadowMode: ShadowModeStatus;
  private emitLock: Promise<void> = Promise.resolve();

  constructor(config: EventEmitterConfig) {
    this.store = config.store;
    this.signedBy = config.signedBy;
    this.enableSignatures = config.enableSignatures ?? false;
    this.signingService = config.signingService;
    this.privateKey = config.privateKey;
    this.listeners = config.listeners ?? [];
    this.shadowMode = config.shadowMode ?? 'production';

    // Validate signing configuration
    if (this.enableSignatures && !this.signingService && !this.privateKey) {
      const isProduction = process.env.NODE_ENV === 'production';
      if (isProduction) {
        throw new Error(
          '[ProofEventEmitter] Signatures enabled but no signingService or privateKey provided in production. ' +
          'Ed25519 signing is required in production to ensure cryptographic integrity.'
        );
      }
      console.warn(
        '[ProofEventEmitter] Signatures enabled but no signingService or privateKey provided. ' +
        'Events will be emitted without signatures (non-production mode).'
      );
    }
  }

  /**
   * Check if signature generation is enabled and configured
   */
  isSigningEnabled(): boolean {
    return this.enableSignatures && (this.signingService?.canSign() || !!this.privateKey);
  }

  /**
   * Check if this emitter is in shadow mode
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
   * Emit a new proof event
   *
   * Events are serialized to ensure proper chaining.
   */
  async emit(request: LogProofEventRequest): Promise<EmitResult> {
    // Serialize event creation to ensure proper chaining
    return this.serializedEmit(request);
  }

  /**
   * Emit an event with specific type helper
   */
  async emitTyped<T extends ProofEventPayload>(
    eventType: ProofEventType,
    correlationId: string,
    payload: T,
    agentId?: string
  ): Promise<EmitResult> {
    return this.emit({
      eventType,
      correlationId,
      payload,
      agentId,
      occurredAt: new Date(),
      signedBy: this.signedBy,
    });
  }

  /**
   * Emit multiple events in a batch
   */
  async emitBatch(
    requests: LogProofEventRequest[],
    options?: BatchEmitOptions
  ): Promise<BatchEmitResult> {
    const events: ProofEvent[] = [];
    const errors: Array<{ index: number; error: Error }> = [];

    for (let i = 0; i < requests.length; i++) {
      try {
        const request = {
          ...requests[i],
          correlationId: options?.correlationId ?? requests[i].correlationId,
        };
        const result = await this.emit(request);
        events.push(result.event);
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        errors.push({ index: i, error: err });
        if (options?.stopOnError) {
          break;
        }
      }
    }

    return {
      events,
      errors,
      success: errors.length === 0,
    };
  }

  /**
   * Add an event listener
   */
  addListener(listener: EventListener): void {
    this.listeners.push(listener);
  }

  /**
   * Remove an event listener
   */
  removeListener(listener: EventListener): void {
    const index = this.listeners.indexOf(listener);
    if (index !== -1) {
      this.listeners.splice(index, 1);
    }
  }

  /**
   * Get the underlying store
   */
  getStore(): ProofEventStore {
    return this.store;
  }

  // Private methods

  private async serializedEmit(request: LogProofEventRequest): Promise<EmitResult> {
    // Wait for any pending emit to complete
    const previousLock = this.emitLock;
    let resolve: () => void;
    this.emitLock = new Promise(r => { resolve = r; });

    try {
      await previousLock;
      return await this.createAndStoreEvent(request);
    } finally {
      resolve!();
    }
  }

  private async createAndStoreEvent(request: LogProofEventRequest): Promise<EmitResult> {
    const now = new Date();
    const eventId = uuidv4();

    // Get previous hash for chaining
    const previousHash = await this.store.getLatestHash() ?? getGenesisHash();
    const isGenesis = previousHash === null;

    // Determine the signer identity
    const signerIdentity = request.signedBy ?? this.signedBy ?? this.signingService?.getServiceId();

    // Build event without hash and signature
    const eventWithoutHashAndSig: Omit<ProofEvent, 'eventHash' | 'recordedAt' | 'signature'> = {
      eventId,
      eventType: request.eventType,
      correlationId: request.correlationId,
      agentId: request.agentId,
      payload: request.payload,
      previousHash,
      occurredAt: request.occurredAt ?? now,
      signedBy: signerIdentity,
      // Tag with shadow mode for T0 sandbox/testnet events
      shadowMode: this.shadowMode !== 'production' ? this.shadowMode : undefined,
    };

    // Generate signature if enabled
    let signature: string | undefined;
    if (this.isSigningEnabled() && signerIdentity) {
      try {
        if (this.signingService?.canSign()) {
          signature = await this.signingService.sign(eventWithoutHashAndSig);
        } else if (this.privateKey) {
          signature = await signEvent(eventWithoutHashAndSig, this.privateKey, signerIdentity);
        }
      } catch (error) {
        const isProduction = process.env.NODE_ENV === 'production';
        if (isProduction) {
          throw new Error(
            `[ProofEventEmitter] Failed to sign event in production: ${error instanceof Error ? error.message : String(error)}. ` +
            'Unsigned events are not permitted in production.'
          );
        }
        console.error('[ProofEventEmitter] Failed to sign event:', error);
        // Continue without signature in non-production - event is still valid for hash chain
      }
    }

    // Build event with signature (for hash computation)
    const eventWithSig: Omit<ProofEvent, 'eventHash' | 'recordedAt'> = {
      ...eventWithoutHashAndSig,
      signature,
    };

    // Compute dual hashes (includes signature if present)
    const eventHash = await computeEventHash(eventWithSig);
    const eventHash3 = computeEventHash3(eventWithSig);

    // Create complete event
    const event: ProofEvent = {
      ...eventWithSig,
      eventHash,
      eventHash3,
      recordedAt: now,
    };

    // Validate the event
    this.validateEvent(event);

    // Store the event
    const storedEvent = await this.store.append(event);

    // Notify listeners
    await this.notifyListeners(storedEvent);

    return {
      event: storedEvent,
      isGenesis,
      previousHash,
    };
  }

  private validateEvent(event: ProofEvent): void {
    if (!event.eventId) {
      throw new EventStoreError(
        'Event ID is required',
        EventStoreErrorCode.INVALID_EVENT
      );
    }
    if (!event.eventType) {
      throw new EventStoreError(
        'Event type is required',
        EventStoreErrorCode.INVALID_EVENT
      );
    }
    if (!event.correlationId) {
      throw new EventStoreError(
        'Correlation ID is required',
        EventStoreErrorCode.INVALID_EVENT
      );
    }
    if (!event.payload) {
      throw new EventStoreError(
        'Event payload is required',
        EventStoreErrorCode.INVALID_EVENT
      );
    }
  }

  private async notifyListeners(event: ProofEvent): Promise<void> {
    for (const listener of this.listeners) {
      try {
        await listener(event);
      } catch (error) {
        // Log but don't throw - listeners shouldn't block event creation
        console.error('Event listener error:', error);
      }
    }
  }
}

/**
 * Create a proof event emitter
 */
export function createEventEmitter(config: EventEmitterConfig): ProofEventEmitter {
  return new ProofEventEmitter(config);
}
