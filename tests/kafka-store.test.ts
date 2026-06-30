import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ProofEvent } from '@vorionsys/contracts';
import type { ProofEventStore } from '../src/events/event-store.js';

// =============================================================================
// Kafka Mock (vi.hoisted for ESM compat)
// =============================================================================

const { mockSend, mockConnect, mockDisconnect, mockSubscribe, mockRun, mockAdminConnect, mockAdminDisconnect, mockListTopics, mockCreateTopics } = vi.hoisted(() => {
  const mockSend = vi.fn().mockResolvedValue([{ topicName: 'vorion.proof-events', partition: 0, errorCode: 0 }]);
  const mockConnect = vi.fn().mockResolvedValue(undefined);
  const mockDisconnect = vi.fn().mockResolvedValue(undefined);
  const mockSubscribe = vi.fn().mockResolvedValue(undefined);
  const mockRun = vi.fn().mockResolvedValue(undefined);
  const mockAdminConnect = vi.fn().mockResolvedValue(undefined);
  const mockAdminDisconnect = vi.fn().mockResolvedValue(undefined);
  const mockListTopics = vi.fn().mockResolvedValue(['vorion.proof-events']);
  const mockCreateTopics = vi.fn().mockResolvedValue(undefined);
  return { mockSend, mockConnect, mockDisconnect, mockSubscribe, mockRun, mockAdminConnect, mockAdminDisconnect, mockListTopics, mockCreateTopics };
});

vi.mock('kafkajs', () => {
  function MockKafka() {
    return {
      producer: () => ({
        connect: mockConnect,
        disconnect: mockDisconnect,
        send: mockSend,
      }),
      consumer: () => ({
        connect: mockConnect,
        disconnect: mockDisconnect,
        subscribe: mockSubscribe,
        run: mockRun,
      }),
      admin: () => ({
        connect: mockAdminConnect,
        disconnect: mockAdminDisconnect,
        listTopics: mockListTopics,
        createTopics: mockCreateTopics,
      }),
    };
  }
  return {
    Kafka: MockKafka,
    CompressionTypes: { GZIP: 1, Snappy: 2, LZ4: 3, None: 0, LZ4: 3, ZSTD: 4 },
    logLevel: { NOTHING: 0, ERROR: 1, WARN: 2, INFO: 3, DEBUG: 4 },
  };
});

import { KafkaEventStore, createKafkaEventStore } from '../src/events/kafka-store.js';

// =============================================================================
// Mock Read Store
// =============================================================================

function mockReadStore(): ProofEventStore {
  const events: ProofEvent[] = [];
  return {
    append: vi.fn(async (event: ProofEvent) => { events.push(event); return event; }),
    get: vi.fn(async (id: string) => events.find(e => e.eventId === id) ?? null),
    getLatest: vi.fn(async () => events[events.length - 1] ?? null),
    getLatestHash: vi.fn(async () => events[events.length - 1]?.previousHash ?? null),
    query: vi.fn(async () => ({ events, totalCount: events.length, hasMore: false })),
    getByCorrelationId: vi.fn(async () => []),
    getByAgentId: vi.fn(async () => []),
    getByTimeRange: vi.fn(async () => []),
    getByType: vi.fn(async () => []),
    getSummaries: vi.fn(async () => []),
    getChain: vi.fn(async () => events),
    count: vi.fn(async () => events.length),
    getStats: vi.fn(async () => ({ totalEvents: events.length, byType: {}, byAgent: {} })),
    exists: vi.fn(async (id: string) => events.some(e => e.eventId === id)),
    clear: vi.fn(async () => { events.length = 0; }),
  };
}

// =============================================================================
// Helpers
// =============================================================================

let counter = 0;
function makeProofEvent(overrides?: Partial<ProofEvent>): ProofEvent {
  return {
    eventId: `evt-${++counter}`,
    eventType: 'GOVERNANCE_DECISION' as unknown as import('@vorionsys/contracts').ProofEventType,
    agentId: 'agent-1',
    occurredAt: new Date(),
    previousHash: 'sha256:' + '0'.repeat(64),
    eventHash: 'sha256:' + 'a'.repeat(64),
    payload: { test: true },
    tenantId: 'tenant-1',
    ...overrides,
  } as unknown as ProofEvent;
}

// =============================================================================
// Tests
// =============================================================================

describe('KafkaEventStore', () => {
  let store: KafkaEventStore;
  let readStore: ProofEventStore;

  beforeEach(() => {
    vi.clearAllMocks();
    counter = 0;
    readStore = mockReadStore();
    store = new KafkaEventStore({
      brokers: ['localhost:9092'],
      readStore,
    });
  });

  afterEach(async () => {
    try { await store.disconnect(); } catch { /* ok */ }
  });

  // =========================================================================
  // Producer
  // =========================================================================

  describe('producer', () => {
    it('should connect producer', async () => {
      await store.connectProducer();
      expect(mockConnect).toHaveBeenCalled();
    });

    it('should publish event to Kafka topic', async () => {
      await store.connectProducer();
      const event = makeProofEvent();

      await store.append(event);

      expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
        topic: 'vorion.proof-events',
        messages: [expect.objectContaining({
          key: event.eventId,
          value: JSON.stringify(event),
        })],
      }));
    });

    it('should use GZIP compression by default', async () => {
      await store.connectProducer();
      await store.append(makeProofEvent());

      expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
        compression: 1, // GZIP
      }));
    });

    it('should include tenant-id in headers', async () => {
      await store.connectProducer();
      await store.append(makeProofEvent({ tenantId: 'acme-corp' } as Partial<ProofEvent>));

      const call = mockSend.mock.calls[0][0];
      expect(call.messages[0].headers['vorion-tenant-id']).toBe('acme-corp');
    });

    it('should throw if producer not connected', async () => {
      await expect(store.append(makeProofEvent())).rejects.toThrow('not connected');
    });

    it('should track totalProduced', async () => {
      await store.connectProducer();
      await store.append(makeProofEvent());
      await store.append(makeProofEvent());
      await store.append(makeProofEvent());

      expect(store.getKafkaStats().totalProduced).toBe(3);
    });
  });

  // =========================================================================
  // Consumer
  // =========================================================================

  describe('consumer', () => {
    it('should subscribe to proof events topic', async () => {
      await store.startConsumer();

      expect(mockSubscribe).toHaveBeenCalledWith(expect.objectContaining({
        topic: 'vorion.proof-events',
        fromBeginning: true,
      }));
    });

    it('should start consuming', async () => {
      await store.startConsumer();

      expect(mockRun).toHaveBeenCalled();
      expect(store.getKafkaStats().consuming).toBe(true);
    });
  });

  // =========================================================================
  // Read Delegation
  // =========================================================================

  describe('read delegation', () => {
    it('should delegate get() to read store', async () => {
      await store.get('evt-1');
      expect(readStore.get).toHaveBeenCalledWith('evt-1');
    });

    it('should delegate query() to read store', async () => {
      await store.query();
      expect(readStore.query).toHaveBeenCalled();
    });

    it('should delegate count() to read store', async () => {
      await store.count();
      expect(readStore.count).toHaveBeenCalled();
    });

    it('should delegate getChain() to read store', async () => {
      await store.getChain('evt-1', 100);
      expect(readStore.getChain).toHaveBeenCalledWith('evt-1', 100);
    });

    it('should delegate getStats() to read store', async () => {
      const stats = await store.getStats();
      expect(readStore.getStats).toHaveBeenCalled();
      expect(stats.totalEvents).toBe(0);
    });
  });

  // =========================================================================
  // Topic Management
  // =========================================================================

  describe('ensureTopic', () => {
    it('should not create topic if it already exists', async () => {
      await store.ensureTopic();

      expect(mockListTopics).toHaveBeenCalled();
      expect(mockCreateTopics).not.toHaveBeenCalled();
    });

    it('should create topic if missing', async () => {
      mockListTopics.mockResolvedValueOnce([]);

      await store.ensureTopic(12, 3);

      expect(mockCreateTopics).toHaveBeenCalledWith(expect.objectContaining({
        topics: [expect.objectContaining({
          topic: 'vorion.proof-events',
          numPartitions: 12,
          replicationFactor: 3,
        })],
      }));
    });
  });

  // =========================================================================
  // Factory
  // =========================================================================

  it('should create via factory', () => {
    const s = createKafkaEventStore({ brokers: ['localhost:9092'], readStore });
    expect(s).toBeInstanceOf(KafkaEventStore);
  });

  // =========================================================================
  // Disconnect
  // =========================================================================

  describe('disconnect', () => {
    it('should disconnect producer and consumer', async () => {
      await store.connectProducer();
      await store.startConsumer();
      await store.disconnect();

      expect(store.getKafkaStats().producerConnected).toBe(false);
      expect(store.getKafkaStats().consuming).toBe(false);
    });
  });
});
