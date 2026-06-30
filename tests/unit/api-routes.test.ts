/**
 * API Routes Tests
 *
 * Comprehensive tests for the Proof Plane REST API route handlers
 * covering event submission, retrieval, verification, chain operations,
 * response formatting, status codes, and error handling.
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
  type Decision,
} from '@vorionsys/contracts';
import {
  ProofPlane,
  createProofPlane,
  createProofRoutes,
  type ProofRoute,
} from '../../src/index.js';

// ─── Route Context Helpers ──────────────────────────────────────────────────

interface MockReply {
  status: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
  _statusCode: number;
  _body: unknown;
}

function createMockReply(): MockReply {
  const reply: MockReply = {
    _statusCode: 200,
    _body: undefined,
    status: vi.fn(),
    send: vi.fn(),
  };
  reply.status.mockImplementation((code: number) => {
    reply._statusCode = code;
    return reply;
  });
  reply.send.mockImplementation((data: unknown) => {
    reply._body = data;
  });
  return reply;
}

function createMockCtx(overrides: {
  params?: unknown;
  query?: unknown;
  body?: unknown;
  id?: string;
} = {}) {
  const reply = createMockReply();
  return {
    ctx: {
      request: {
        params: overrides.params,
        query: overrides.query,
        body: overrides.body,
        id: overrides.id ?? 'req-' + uuidv4(),
      },
      reply,
    },
    reply,
  };
}

function findRoute(routes: ProofRoute[], method: string, path: string): ProofRoute {
  const route = routes.find((r) => r.method === method && r.path === path);
  if (!route) throw new Error(`Route ${method} ${path} not found`);
  return route;
}

// ─── Test Data Helpers ──────────────────────────────────────────────────────

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
    justification: 'Test intent',
    createdAt: new Date(),
    ...overrides,
  };
}

function createDecision(overrides: Partial<Decision> = {}): Decision {
  return {
    decisionId: uuidv4(),
    intentId: uuidv4(),
    agentId: uuidv4(),
    correlationId: uuidv4(),
    permitted: true,
    trustBand: TrustBand.T3_MONITORED,
    trustScore: 65,
    reasoning: ['test'],
    decidedAt: new Date(),
    expiresAt: new Date(Date.now() + 300000),
    latencyMs: 3,
    version: 1,
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Proof Plane API Routes', () => {
  let pp: ProofPlane;
  let routes: ProofRoute[];

  beforeEach(() => {
    pp = createProofPlane({ signedBy: 'routes-test', enableSignatures: false });
    routes = createProofRoutes(pp);
  });

  // ── Route Registration ──────────────────────────────────────────────

  describe('route registration', () => {
    it('should register all expected routes', () => {
      expect(routes.length).toBeGreaterThanOrEqual(7);
    });

    it('should include POST /proof route', () => {
      const route = findRoute(routes, 'POST', '/proof');
      expect(route).toBeDefined();
      expect(route.schema?.body).toBeDefined();
    });

    it('should include GET /proof/:id route', () => {
      const route = findRoute(routes, 'GET', '/proof/:id');
      expect(route).toBeDefined();
      expect(route.schema?.params).toBeDefined();
    });

    it('should include GET /proof/verify/:id route', () => {
      const route = findRoute(routes, 'GET', '/proof/verify/:id');
      expect(route).toBeDefined();
    });

    it('should include GET /proof/chain/:correlationId route', () => {
      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      expect(route).toBeDefined();
    });

    it('should include POST /proof/chain/verify route', () => {
      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      expect(route).toBeDefined();
    });

    it('should include GET /proof/stats route', () => {
      const route = findRoute(routes, 'GET', '/proof/stats');
      expect(route).toBeDefined();
    });

    it('should include GET /proof/latest route', () => {
      const route = findRoute(routes, 'GET', '/proof/latest');
      expect(route).toBeDefined();
    });
  });

  // ── POST /proof ─────────────────────────────────────────────────────

  describe('POST /proof', () => {
    it('should accept a valid proof event and return 201', async () => {
      const correlationId = uuidv4();
      const { ctx, reply } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId,
          payload: {
            type: 'intent_received',
            intentId: uuidv4(),
            action: 'read-file',
            actionType: 'read',
            resourceScope: ['/data'],
          },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(201);
      expect(reply._body).toBeDefined();
      const body = reply._body as { data: { eventId: string; correlationId: string } };
      expect(body.data.eventId).toBeTruthy();
      expect(body.data.correlationId).toBe(correlationId);
    });

    it('should include eventHash in the response', async () => {
      const { ctx, reply } = createMockCtx({
        body: {
          eventType: ProofEventType.DECISION_MADE,
          correlationId: uuidv4(),
          payload: {
            type: 'decision_made',
            decisionId: uuidv4(),
            intentId: uuidv4(),
            permitted: true,
            trustBand: 'T2_PROVISIONAL',
            trustScore: 55,
            reasoning: ['test'],
          },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await route.handler(ctx, pp);

      const body = reply._body as { data: { eventHash: string } };
      expect(body.data.eventHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should include previousHash in the response', async () => {
      // Emit a first event so we have a chain
      await pp.logIntentReceived(createIntent());

      const { ctx, reply } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: uuidv4(),
          payload: {
            type: 'intent_received',
            intentId: uuidv4(),
            action: 'test',
            actionType: 'read',
            resourceScope: [],
          },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await route.handler(ctx, pp);

      const body = reply._body as { data: { previousHash: string | null } };
      expect(body.data.previousHash).toBeTruthy();
    });

    it('should accept optional agentId', async () => {
      const agentId = uuidv4();
      const { ctx, reply } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: uuidv4(),
          agentId,
          payload: {
            type: 'intent_received',
            intentId: uuidv4(),
            action: 'test',
            actionType: 'read',
            resourceScope: [],
          },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(201);
    });

    it('should reject invalid eventType', async () => {
      const { ctx } = createMockCtx({
        body: {
          eventType: 'INVALID_TYPE',
          correlationId: uuidv4(),
          payload: { type: 'test' },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should reject non-UUID correlationId', async () => {
      const { ctx } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: 'not-a-uuid',
          payload: { type: 'intent_received' },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should reject missing payload', async () => {
      const { ctx } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: uuidv4(),
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should reject empty body', async () => {
      const { ctx } = createMockCtx({ body: {} });

      const route = findRoute(routes, 'POST', '/proof');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should reject non-object payload', async () => {
      const { ctx } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: uuidv4(),
          payload: 'string-payload',
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should include meta with timestamp in the response', async () => {
      const requestId = 'req-123';
      const { ctx, reply } = createMockCtx({
        id: requestId,
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: uuidv4(),
          payload: {
            type: 'intent_received',
            intentId: uuidv4(),
            action: 'test',
            actionType: 'read',
            resourceScope: [],
          },
        },
      });

      const route = findRoute(routes, 'POST', '/proof');
      await route.handler(ctx, pp);

      const body = reply._body as { meta: { requestId: string; timestamp: string } };
      expect(body.meta.requestId).toBe(requestId);
      expect(body.meta.timestamp).toBeTruthy();
      // Timestamp should be ISO-8601
      expect(() => new Date(body.meta.timestamp)).not.toThrow();
    });

    it('should return 500 when emitter throws', async () => {
      // Create a proof plane with a store that will fail
      const failingStore = {
        append: vi.fn().mockRejectedValue(new Error('Store failure')),
        get: vi.fn(),
        getLatest: vi.fn(),
        getChain: vi.fn(),
        getByCorrelationId: vi.fn(),
        getByAgentId: vi.fn(),
        getByType: vi.fn(),
        query: vi.fn(),
        count: vi.fn(),
        getStats: vi.fn(),
        clear: vi.fn(),
      };
      const failPp = createProofPlane({ store: failingStore as any, enableSignatures: false });
      const failRoutes = createProofRoutes(failPp);

      const { ctx, reply } = createMockCtx({
        body: {
          eventType: ProofEventType.INTENT_RECEIVED,
          correlationId: uuidv4(),
          payload: {
            type: 'intent_received',
            intentId: uuidv4(),
            action: 'test',
            actionType: 'read',
            resourceScope: [],
          },
        },
      });

      const route = findRoute(failRoutes, 'POST', '/proof');
      await route.handler(ctx, failPp);

      expect(reply._statusCode).toBe(500);
      const body = reply._body as { error: { code: string; message: string } };
      expect(body.error.code).toBe('EMIT_FAILED');
      expect(body.error.message).toContain('Failed to emit');
    });
  });

  // ── GET /proof/:id ──────────────────────────────────────────────────

  describe('GET /proof/:id', () => {
    it('should return 200 with event data for valid ID', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);

      const { ctx, reply } = createMockCtx({
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as { data: { eventId: string } };
      expect(body.data.eventId).toBe(result.event.eventId);
    });

    it('should return 404 for non-existent event ID', async () => {
      const nonExistentId = uuidv4();
      const { ctx, reply } = createMockCtx({
        params: { id: nonExistentId },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(404);
      const body = reply._body as { error: { code: string; message: string } };
      expect(body.error.code).toBe('EVENT_NOT_FOUND');
      expect(body.error.message).toContain(nonExistentId);
    });

    it('should reject invalid UUID in params', async () => {
      const { ctx } = createMockCtx({
        params: { id: 'not-a-uuid' },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should reject missing id param', async () => {
      const { ctx } = createMockCtx({
        params: {},
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should include request ID in response meta', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);
      const requestId = 'my-request-id';

      const { ctx, reply } = createMockCtx({
        id: requestId,
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await route.handler(ctx, pp);

      const body = reply._body as { meta: { requestId: string } };
      expect(body.meta.requestId).toBe(requestId);
    });
  });

  // ── GET /proof/verify/:id ───────────────────────────────────────────

  describe('GET /proof/verify/:id', () => {
    it('should return verification result for valid event', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);

      const { ctx, reply } = createMockCtx({
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/verify/:id');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as {
        data: {
          eventId: string;
          verification: {
            hashValid: boolean;
            hash3Valid: boolean;
            computedHash: string;
            storedHash: string;
            verifiedAt: string;
          };
        };
      };
      expect(body.data.eventId).toBe(result.event.eventId);
      expect(body.data.verification.hashValid).toBe(true);
      expect(body.data.verification.hash3Valid).toBe(true);
      expect(body.data.verification.computedHash).toBe(body.data.verification.storedHash);
    });

    it('should return 404 for non-existent event', async () => {
      const { ctx, reply } = createMockCtx({
        params: { id: uuidv4() },
      });

      const route = findRoute(routes, 'GET', '/proof/verify/:id');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(404);
      const body = reply._body as { error: { code: string } };
      expect(body.error.code).toBe('EVENT_NOT_FOUND');
    });

    it('should reject invalid UUID', async () => {
      const { ctx } = createMockCtx({
        params: { id: 'bad-id' },
      });

      const route = findRoute(routes, 'GET', '/proof/verify/:id');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should include signatureValid as null when no signing service', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);

      const { ctx, reply } = createMockCtx({
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/verify/:id');
      await route.handler(ctx, pp);

      const body = reply._body as {
        data: { verification: { signatureValid: boolean | null } };
      };
      expect(body.data.verification.signatureValid).toBeNull();
    });

    it('should include verifiedAt timestamp', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);

      const { ctx, reply } = createMockCtx({
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/verify/:id');
      await route.handler(ctx, pp);

      const body = reply._body as {
        data: { verification: { verifiedAt: string } };
      };
      expect(body.data.verification.verifiedAt).toBeTruthy();
      expect(() => new Date(body.data.verification.verifiedAt)).not.toThrow();
    });
  });

  // ── GET /proof/chain/:correlationId ─────────────────────────────────

  describe('GET /proof/chain/:correlationId', () => {
    it('should return events for a correlation ID', async () => {
      const correlationId = uuidv4();
      const intent = createIntent({ correlationId });
      const decision = createDecision({ correlationId });

      await pp.logIntentReceived(intent);
      await pp.logDecisionMade(decision);

      const { ctx, reply } = createMockCtx({
        params: { correlationId },
      });

      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as {
        data: {
          correlationId: string;
          events: unknown[];
          total: number;
          pagination: { offset: number; limit: number; hasMore: boolean };
        };
      };
      expect(body.data.correlationId).toBe(correlationId);
      expect(body.data.events).toHaveLength(2);
      expect(body.data.total).toBe(2);
    });

    it('should return 404 when no events for correlation ID', async () => {
      const { ctx, reply } = createMockCtx({
        params: { correlationId: uuidv4() },
      });

      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(404);
      const body = reply._body as { error: { code: string } };
      expect(body.error.code).toBe('TRACE_NOT_FOUND');
    });

    it('should reject invalid UUID for correlationId', async () => {
      const { ctx } = createMockCtx({
        params: { correlationId: 'not-valid' },
      });

      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should support pagination with limit and offset', async () => {
      const correlationId = uuidv4();
      // Create 5 events
      for (let i = 0; i < 5; i++) {
        await pp.logEvent(
          ProofEventType.INTENT_RECEIVED,
          correlationId,
          {
            type: 'intent_received',
            intentId: uuidv4(),
            action: `action-${i}`,
            actionType: 'read',
            resourceScope: [],
          },
        );
      }

      const { ctx, reply } = createMockCtx({
        params: { correlationId },
        query: { limit: 2, offset: 1 },
      });

      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as {
        data: {
          events: unknown[];
          total: number;
          pagination: { offset: number; limit: number; hasMore: boolean };
        };
      };
      expect(body.data.events).toHaveLength(2);
      expect(body.data.total).toBe(5);
      expect(body.data.pagination.offset).toBe(1);
      expect(body.data.pagination.limit).toBe(2);
      expect(body.data.pagination.hasMore).toBe(true);
    });

    it('should default pagination to offset=0 and limit=100', async () => {
      const correlationId = uuidv4();
      await pp.logEvent(
        ProofEventType.INTENT_RECEIVED,
        correlationId,
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: [],
        },
      );

      const { ctx, reply } = createMockCtx({
        params: { correlationId },
      });

      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      await route.handler(ctx, pp);

      const body = reply._body as {
        data: { pagination: { offset: number; limit: number } };
      };
      expect(body.data.pagination.offset).toBe(0);
      expect(body.data.pagination.limit).toBe(100);
    });

    it('should set hasMore to false when all events fit', async () => {
      const correlationId = uuidv4();
      await pp.logEvent(
        ProofEventType.INTENT_RECEIVED,
        correlationId,
        {
          type: 'intent_received',
          intentId: uuidv4(),
          action: 'test',
          actionType: 'read',
          resourceScope: [],
        },
      );

      const { ctx, reply } = createMockCtx({
        params: { correlationId },
      });

      const route = findRoute(routes, 'GET', '/proof/chain/:correlationId');
      await route.handler(ctx, pp);

      const body = reply._body as {
        data: { pagination: { hasMore: boolean } };
      };
      expect(body.data.pagination.hasMore).toBe(false);
    });
  });

  // ── POST /proof/chain/verify ────────────────────────────────────────

  describe('POST /proof/chain/verify', () => {
    it('should verify an empty chain successfully', async () => {
      const { ctx, reply } = createMockCtx({
        body: {},
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as {
        data: {
          chain: { valid: boolean; verifiedCount: number; totalEvents: number };
          signatures: null;
          fullyVerified: boolean;
          verifiedAt: string;
        };
      };
      expect(body.data.chain.valid).toBe(true);
      expect(body.data.chain.totalEvents).toBe(0);
      expect(body.data.fullyVerified).toBe(true);
    });

    it('should verify chain with events', async () => {
      await pp.logIntentReceived(createIntent());
      await pp.logDecisionMade(createDecision());
      await pp.logIntentReceived(createIntent());

      const { ctx, reply } = createMockCtx({
        body: {},
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as {
        data: {
          chain: { valid: boolean; verifiedCount: number; totalEvents: number };
          fullyVerified: boolean;
        };
      };
      expect(body.data.chain.valid).toBe(true);
      expect(body.data.chain.verifiedCount).toBe(3);
      expect(body.data.chain.totalEvents).toBe(3);
      expect(body.data.fullyVerified).toBe(true);
    });

    it('should accept optional limit parameter', async () => {
      await pp.logIntentReceived(createIntent());
      await pp.logDecisionMade(createDecision());
      await pp.logIntentReceived(createIntent());

      const { ctx, reply } = createMockCtx({
        body: { limit: 2 },
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
    });

    it('should accept optional fromEventId parameter', async () => {
      const result = await pp.logIntentReceived(createIntent());

      const { ctx, reply } = createMockCtx({
        body: { fromEventId: result.event.eventId },
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
    });

    it('should reject invalid fromEventId (non-UUID)', async () => {
      const { ctx } = createMockCtx({
        body: { fromEventId: 'not-uuid' },
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await expect(route.handler(ctx, pp)).rejects.toThrow();
    });

    it('should include signatures as null when signing is not configured', async () => {
      const { ctx, reply } = createMockCtx({
        body: {},
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      const body = reply._body as { data: { signatures: null } };
      expect(body.data.signatures).toBeNull();
    });

    it('should include verifiedAt timestamp', async () => {
      const { ctx, reply } = createMockCtx({
        body: {},
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      const body = reply._body as { data: { verifiedAt: string } };
      expect(body.data.verifiedAt).toBeTruthy();
      expect(() => new Date(body.data.verifiedAt)).not.toThrow();
    });

    it('should include firstEventId and lastEventId', async () => {
      const r1 = await pp.logIntentReceived(createIntent());
      await pp.logDecisionMade(createDecision());
      const r3 = await pp.logIntentReceived(createIntent());

      const { ctx, reply } = createMockCtx({
        body: {},
      });

      const route = findRoute(routes, 'POST', '/proof/chain/verify');
      await route.handler(ctx, pp);

      const body = reply._body as {
        data: {
          chain: { firstEventId: string; lastEventId: string };
        };
      };
      expect(body.data.chain.firstEventId).toBe(r1.event.eventId);
      expect(body.data.chain.lastEventId).toBe(r3.event.eventId);
    });
  });

  // ── GET /proof/stats ────────────────────────────────────────────────

  describe('GET /proof/stats', () => {
    it('should return stats for empty store', async () => {
      const { ctx, reply } = createMockCtx();

      const route = findRoute(routes, 'GET', '/proof/stats');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as { data: { totalEvents: number } };
      expect(body.data.totalEvents).toBe(0);
    });

    it('should return correct event counts by type', async () => {
      await pp.logIntentReceived(createIntent());
      await pp.logIntentReceived(createIntent());
      await pp.logDecisionMade(createDecision());

      const { ctx, reply } = createMockCtx();

      const route = findRoute(routes, 'GET', '/proof/stats');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as {
        data: {
          totalEvents: number;
          eventsByType: Record<string, number>;
        };
      };
      expect(body.data.totalEvents).toBe(3);
      expect(body.data.eventsByType[ProofEventType.INTENT_RECEIVED]).toBe(2);
      expect(body.data.eventsByType[ProofEventType.DECISION_MADE]).toBe(1);
    });
  });

  // ── GET /proof/latest ───────────────────────────────────────────────

  describe('GET /proof/latest', () => {
    it('should return 404 when no events exist', async () => {
      const { ctx, reply } = createMockCtx();

      const route = findRoute(routes, 'GET', '/proof/latest');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(404);
      const body = reply._body as { error: { code: string } };
      expect(body.error.code).toBe('NO_EVENTS');
    });

    it('should return the most recent event', async () => {
      await pp.logIntentReceived(createIntent());
      const lastResult = await pp.logDecisionMade(createDecision());

      const { ctx, reply } = createMockCtx();

      const route = findRoute(routes, 'GET', '/proof/latest');
      await route.handler(ctx, pp);

      expect(reply._statusCode).toBe(200);
      const body = reply._body as { data: { eventId: string } };
      expect(body.data.eventId).toBe(lastResult.event.eventId);
    });
  });

  // ── Response Envelope ───────────────────────────────────────────────

  describe('response envelope', () => {
    it('success responses should have data and meta properties', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);

      const { ctx, reply } = createMockCtx({
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await route.handler(ctx, pp);

      const body = reply._body as { data: unknown; meta: unknown };
      expect(body).toHaveProperty('data');
      expect(body).toHaveProperty('meta');
    });

    it('error responses should have error property with code and message', async () => {
      const { ctx, reply } = createMockCtx({
        params: { id: uuidv4() },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await route.handler(ctx, pp);

      const body = reply._body as { error: { code: string; message: string } };
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(typeof body.error.code).toBe('string');
      expect(typeof body.error.message).toBe('string');
    });

    it('meta.timestamp should be ISO-8601 format', async () => {
      const intent = createIntent();
      const result = await pp.logIntentReceived(intent);

      const { ctx, reply } = createMockCtx({
        params: { id: result.event.eventId },
      });

      const route = findRoute(routes, 'GET', '/proof/:id');
      await route.handler(ctx, pp);

      const body = reply._body as { meta: { timestamp: string } };
      const parsed = new Date(body.meta.timestamp);
      expect(parsed.toISOString()).toBe(body.meta.timestamp);
    });
  });
});
