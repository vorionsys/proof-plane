/**
 * Kafka Consumer Pool — parallel proof event materialization.
 *
 * Runs N consumers in the same consumer group to parallelize proof writes.
 * KafkaJS within a single process handles partition assignment automatically
 * when multiple consumers share a group ID, but each consumer needs a
 * unique client ID.
 *
 * For cross-process scaling (multiple K8s pods), each pod runs its own
 * consumer pool — Kafka rebalances partitions across pods automatically.
 *
 * Architecture:
 *   N consumers × M partitions = min(N, M) active readers
 *   If N > M, extra consumers are idle standby (instant failover)
 *
 * @packageDocumentation
 */

import { Kafka, Consumer, logLevel, type KafkaConfig } from 'kafkajs';
import type { ProofEvent } from '@vorionsys/contracts';
import type { ProofEventStore } from './event-store.js';

// =============================================================================
// Configuration
// =============================================================================

export interface KafkaConsumerPoolConfig {
  /** Kafka broker addresses */
  brokers: string[];
  /** Topic to consume from (default: vorion.proof-events) */
  topic?: string;
  /** Consumer group ID (default: vorion-proof-materializer) */
  groupId?: string;
  /** Client ID prefix — each consumer gets {prefix}-{index} */
  clientIdPrefix?: string;
  /** Number of parallel consumers (default: 3) */
  poolSize?: number;
  /** Read store for materializing events */
  readStore: ProofEventStore;
  /** SASL authentication (optional) */
  sasl?: KafkaConfig['sasl'];
  /** SSL configuration (optional) */
  ssl?: KafkaConfig['ssl'];
  /** Error handler for individual consumer failures */
  onError?: (consumerId: string, error: unknown) => void;
}

const DEFAULT_TOPIC = 'vorion.proof-events';
const DEFAULT_GROUP = 'vorion-proof-materializer';
const DEFAULT_CLIENT_PREFIX = 'vorion-proof-consumer';

// =============================================================================
// Consumer Pool
// =============================================================================

export class KafkaConsumerPool {
  private readonly consumers: Array<{ id: string; consumer: Consumer; kafka: Kafka }> = [];
  private readonly config: Required<Pick<KafkaConsumerPoolConfig, 'topic' | 'groupId' | 'poolSize' | 'clientIdPrefix'>> & KafkaConsumerPoolConfig;
  private readonly readStore: ProofEventStore;
  private running = false;
  private totalConsumed = 0;
  private totalErrors = 0;

  constructor(config: KafkaConsumerPoolConfig) {
    this.config = {
      topic: DEFAULT_TOPIC,
      groupId: DEFAULT_GROUP,
      clientIdPrefix: DEFAULT_CLIENT_PREFIX,
      poolSize: 3,
      ...config,
    };
    this.readStore = config.readStore;
  }

  /**
   * Start all consumers in the pool.
   * Each consumer connects to Kafka and subscribes to the topic.
   * Kafka rebalances partitions across consumers in the same group.
   */
  async start(): Promise<void> {
    if (this.running) return;

    const startPromises: Promise<void>[] = [];

    for (let i = 0; i < this.config.poolSize; i++) {
      const clientId = `${this.config.clientIdPrefix}-${i}`;
      const kafka = new Kafka({
        clientId,
        brokers: this.config.brokers,
        sasl: this.config.sasl,
        ssl: this.config.ssl,
        logLevel: logLevel.WARN,
      });

      const consumer = kafka.consumer({
        groupId: this.config.groupId,
        sessionTimeout: 30_000,
        heartbeatInterval: 3_000,
      });

      this.consumers.push({ id: clientId, consumer, kafka });

      startPromises.push(
        this.startConsumer(clientId, consumer)
      );
    }

    await Promise.all(startPromises);
    this.running = true;
  }

  /**
   * Stop all consumers gracefully.
   */
  async stop(): Promise<void> {
    this.running = false;
    const stopPromises = this.consumers.map(async ({ id, consumer }) => {
      try {
        await consumer.disconnect();
      } catch (err) {
        this.config.onError?.(id, err);
      }
    });
    await Promise.all(stopPromises);
    this.consumers.length = 0;
  }

  /**
   * Pool statistics.
   */
  get stats() {
    return {
      poolSize: this.config.poolSize,
      activeConsumers: this.consumers.length,
      totalConsumed: this.totalConsumed,
      totalErrors: this.totalErrors,
      running: this.running,
    };
  }

  // =========================================================================
  // Internal
  // =========================================================================

  private async startConsumer(id: string, consumer: Consumer): Promise<void> {
    await consumer.connect();
    await consumer.subscribe({ topic: this.config.topic, fromBeginning: false });

    await consumer.run({
      eachMessage: async ({ message }) => {
        if (!message.value) return;

        try {
          const event = JSON.parse(message.value.toString()) as ProofEvent;
          await this.readStore.append(event);
          this.totalConsumed++;
        } catch (err) {
          this.totalErrors++;
          this.config.onError?.(id, err);
        }
      },
    });
  }
}
