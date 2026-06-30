/**
 * Event Emitter Coverage Tests
 *
 * Covers untested branches in event-emitter.ts:
 * - validateEvent error paths (missing eventId, eventType, correlationId, payload)
 * - emitBatch with stopOnError
 * - listener error handling
 * - shadow mode emitter
 * - signing error paths
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type LogProofEventRequest } from '@vorionsys/contracts';
import {
  ProofEventEmitter,
  createEventEmitter,
  createInMemoryEventStore,
  EventStoreError,
  EventStoreErrorCode,
  type InMemoryEventStore,
} from '../../src/index.js';

function makeRequest(overrides: Partial<LogProofEventRequest> = {}): LogProofEventRequest {
  return {
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
    occurredAt: new Date(),
    signedBy: 'test',
    ...overrides,
  };
}

describe('ProofEventEmitter — validation error paths', () => {
  let store: InMemoryEventStore;
  let emitter: ProofEventEmitter;

  beforeEach(() => {
    store = createInMemoryEventStore();
    emitter = createEventEmitter({ store });
  });

  it('throws INVALID_EVENT for missing eventType', async () => {
    try {
      await emitter.emit(makeRequest({ eventType: '' as any }));
      expect.unreachable('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EventStoreError);
      expect((err as EventStoreError).code).toBe(EventStoreErrorCode.INVALID_EVENT);
    }
  });

  it('throws INVALID_EVENT for missing correlationId', async () => {
    try {
      await emitter.emit(makeRequest({ correlationId: '' }));
      expect.unreachable('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EventStoreError);
      expect((err as EventStoreError).code).toBe(EventStoreErrorCode.INVALID_EVENT);
    }
  });

  it('throws INVALID_EVENT for missing payload', async () => {
    try {
      await emitter.emit(makeRequest({ payload: null as any }));
      expect.unreachable('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EventStoreError);
      expect((err as EventStoreError).code).toBe(EventStoreErrorCode.INVALID_EVENT);
    }
  });
});

describe('ProofEventEmitter — batch emit', () => {
  let store: InMemoryEventStore;
  let emitter: ProofEventEmitter;

  beforeEach(() => {
    store = createInMemoryEventStore();
    emitter = createEventEmitter({ store });
  });

  it('emits multiple events in batch', async () => {
    const result = await emitter.emitBatch([
      makeRequest(),
      makeRequest(),
      makeRequest(),
    ]);

    expect(result.events).toHaveLength(3);
    expect(result.errors).toHaveLength(0);
    expect(result.success).toBe(true);
  });

  it('uses shared correlationId from options', async () => {
    const sharedCorr = uuidv4();
    const result = await emitter.emitBatch(
      [makeRequest(), makeRequest()],
      { correlationId: sharedCorr },
    );

    expect(result.events[0].correlationId).toBe(sharedCorr);
    expect(result.events[1].correlationId).toBe(sharedCorr);
  });

  it('continues on error by default', async () => {
    const result = await emitter.emitBatch([
      makeRequest(),
      makeRequest({ correlationId: '' }), // will fail validation
      makeRequest(),
    ]);

    expect(result.events).toHaveLength(2);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].index).toBe(1);
    expect(result.success).toBe(false);
  });

  it('stops on first error when stopOnError is true', async () => {
    const result = await emitter.emitBatch(
      [
        makeRequest({ correlationId: '' }), // fails
        makeRequest(), // should not run
      ],
      { stopOnError: true },
    );

    expect(result.events).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
  });

  it('wraps non-Error exceptions in Error', async () => {
    // Mock store to throw a non-Error
    const failStore = {
      ...store,
      getLatestHash: vi.fn().mockRejectedValue('string error'),
      append: vi.fn(),
    };
    const failEmitter = createEventEmitter({ store: failStore as any });

    const result = await failEmitter.emitBatch([makeRequest()]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error).toBeInstanceOf(Error);
  });
});

describe('ProofEventEmitter — listener error handling', () => {
  it('catches and logs listener errors without blocking', async () => {
    const store = createInMemoryEventStore();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const emitter = createEventEmitter({
      store,
      listeners: [
        () => { throw new Error('listener boom'); },
      ],
    });

    // Should not throw despite listener error
    const result = await emitter.emit(makeRequest());
    expect(result.event).toBeDefined();
    expect(errorSpy).toHaveBeenCalled();

    errorSpy.mockRestore();
  });
});

describe('ProofEventEmitter — shadow mode', () => {
  it('tags events with shadow mode', async () => {
    const store = createInMemoryEventStore();
    const emitter = createEventEmitter({ store, shadowMode: 'shadow' });

    expect(emitter.isShadowMode()).toBe(true);
    expect(emitter.getShadowMode()).toBe('shadow');

    const result = await emitter.emit(makeRequest());
    expect(result.event.shadowMode).toBe('shadow');
  });

  it('production mode does not set shadowMode field', async () => {
    const store = createInMemoryEventStore();
    const emitter = createEventEmitter({ store, shadowMode: 'production' });

    expect(emitter.isShadowMode()).toBe(false);

    const result = await emitter.emit(makeRequest());
    expect(result.event.shadowMode).toBeUndefined();
  });
});

describe('ProofEventEmitter — signing', () => {
  it('isSigningEnabled returns false without keys', () => {
    const store = createInMemoryEventStore();
    const emitter = createEventEmitter({ store, enableSignatures: true });
    expect(emitter.isSigningEnabled()).toBe(false);
  });

  it('getStore returns the underlying store', () => {
    const store = createInMemoryEventStore();
    const emitter = createEventEmitter({ store });
    expect(emitter.getStore()).toBe(store);
  });
});
