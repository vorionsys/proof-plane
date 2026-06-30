/**
 * Persistent Store Enforcement Tests (Gap 6)
 *
 * Validates that:
 * - InMemoryEventStore.persistent === false
 * - Persistent stores report persistent === true
 * - ProofPlane refuses to start in production with a non-persistent store
 * - VORION_ALLOW_MEMORY_STORE=true bypasses the check with a warning
 * - Non-production environments are unaffected
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { InMemoryEventStore, createInMemoryEventStore } from '../../src/index.js';
import { ProofPlane } from '../../src/proof-plane/proof-plane.js';
import type { ProofEventStore } from '../../src/events/event-store.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Minimal stub that satisfies ProofEventStore with persistent=true.
 * We only need the two new properties for these tests; methods are stubs.
 */
function createPersistentStoreStub(): ProofEventStore {
  return {
    persistent: true,
    storeType: 'stub-persistent',
    append: vi.fn(),
    get: vi.fn(),
    getLatest: vi.fn().mockResolvedValue(null),
    getLatestHash: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue({ events: [], totalCount: 0, hasMore: false }),
    getByCorrelationId: vi.fn().mockResolvedValue([]),
    getByAgentId: vi.fn().mockResolvedValue([]),
    getByTimeRange: vi.fn().mockResolvedValue([]),
    getByType: vi.fn().mockResolvedValue([]),
    getSummaries: vi.fn().mockResolvedValue([]),
    getChain: vi.fn().mockResolvedValue([]),
    count: vi.fn().mockResolvedValue(0),
    getStats: vi.fn().mockResolvedValue({ totalEvents: 0, byType: {}, byAgent: {} }),
    exists: vi.fn().mockResolvedValue(false),
    clear: vi.fn(),
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Persistent Store Enforcement (Gap 6)', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalAllowMemory = process.env.VORION_ALLOW_MEMORY_STORE;

  afterEach(() => {
    // Restore env vars after each test
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }
    if (originalAllowMemory === undefined) {
      delete process.env.VORION_ALLOW_MEMORY_STORE;
    } else {
      process.env.VORION_ALLOW_MEMORY_STORE = originalAllowMemory;
    }
    vi.restoreAllMocks();
  });

  // ── Property assertions ────────────────────────────────────────────────

  describe('store.persistent property', () => {
    it('InMemoryEventStore.persistent is false', () => {
      const store = createInMemoryEventStore();
      expect(store.persistent).toBe(false);
    });

    it('InMemoryEventStore.storeType is "in-memory"', () => {
      const store = new InMemoryEventStore();
      expect(store.storeType).toBe('in-memory');
    });

    it('persistent store stub returns persistent === true', () => {
      const store = createPersistentStoreStub();
      expect(store.persistent).toBe(true);
      expect(store.storeType).toBe('stub-persistent');
    });
  });

  // ── Production guard ───────────────────────────────────────────────────

  describe('production guard', () => {
    it('throws when NODE_ENV=production and store is not persistent', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.VORION_ALLOW_MEMORY_STORE;

      expect(() => {
        new ProofPlane({
          store: createInMemoryEventStore(),
          enableSignatures: false,
        });
      }).toThrow(/FATAL.*Cannot use in-memory event store in production/);
    });

    it('error message mentions VORION_ALLOW_MEMORY_STORE', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.VORION_ALLOW_MEMORY_STORE;

      expect(() => {
        new ProofPlane({
          store: createInMemoryEventStore(),
          enableSignatures: false,
        });
      }).toThrow(/VORION_ALLOW_MEMORY_STORE/);
    });

    it('does NOT throw in production with a persistent store', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.VORION_ALLOW_MEMORY_STORE;

      expect(() => {
        new ProofPlane({
          store: createPersistentStoreStub(),
          enableSignatures: false,
        });
      }).not.toThrow();
    });

    it('does NOT throw when NODE_ENV is not production', () => {
      process.env.NODE_ENV = 'test';
      delete process.env.VORION_ALLOW_MEMORY_STORE;

      expect(() => {
        new ProofPlane({
          store: createInMemoryEventStore(),
          enableSignatures: false,
        });
      }).not.toThrow();
    });

    it('does NOT throw when NODE_ENV is undefined', () => {
      delete process.env.NODE_ENV;
      delete process.env.VORION_ALLOW_MEMORY_STORE;

      expect(() => {
        new ProofPlane({
          store: createInMemoryEventStore(),
          enableSignatures: false,
        });
      }).not.toThrow();
    });
  });

  // ── Escape hatch ───────────────────────────────────────────────────────

  describe('VORION_ALLOW_MEMORY_STORE escape hatch', () => {
    it('bypasses the check when VORION_ALLOW_MEMORY_STORE=true', () => {
      process.env.NODE_ENV = 'production';
      process.env.VORION_ALLOW_MEMORY_STORE = 'true';

      expect(() => {
        new ProofPlane({
          store: createInMemoryEventStore(),
          enableSignatures: false,
        });
      }).not.toThrow();
    });

    it('emits a console warning when escape hatch is used', () => {
      process.env.NODE_ENV = 'production';
      process.env.VORION_ALLOW_MEMORY_STORE = 'true';
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      new ProofPlane({
        store: createInMemoryEventStore(),
        enableSignatures: false,
      });

      const warningCalls = warnSpy.mock.calls.flat().join(' ');
      expect(warningCalls).toContain('non-persistent event store');
      expect(warningCalls).toContain('VORION_ALLOW_MEMORY_STORE');
    });

    it('still throws when VORION_ALLOW_MEMORY_STORE is not exactly "true"', () => {
      process.env.NODE_ENV = 'production';
      process.env.VORION_ALLOW_MEMORY_STORE = 'yes';

      expect(() => {
        new ProofPlane({
          store: createInMemoryEventStore(),
          enableSignatures: false,
        });
      }).toThrow(/FATAL/);
    });
  });
});
