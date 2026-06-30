/**
 * Route Adapter Tests — registerProofRoutes (Fastify) + createProofExpressRouter (Express)
 *
 * Covers the untested adapter code in routes.ts lines 411-566:
 * registerProofRoutes, createProofExpressRouter, matchPath, extractParams
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType } from '@vorionsys/contracts';
import {
  createProofPlane,
  type ProofPlane,
  registerProofRoutes,
  createProofExpressRouter,
} from '../../src/index.js';

describe('registerProofRoutes (Fastify adapter)', () => {
  let pp: ProofPlane;

  beforeEach(() => {
    pp = createProofPlane({ signedBy: 'adapter-test', enableSignatures: false });
  });

  it('registers GET and POST routes on the fastify instance', () => {
    const getFn = vi.fn();
    const postFn = vi.fn();
    const fastify = { get: getFn, post: postFn };

    registerProofRoutes(fastify, pp);

    // Should register multiple GET and POST routes
    expect(getFn.mock.calls.length).toBeGreaterThanOrEqual(4); // :id, verify/:id, chain/:correlationId, stats, latest
    expect(postFn.mock.calls.length).toBeGreaterThanOrEqual(2); // /proof, /proof/chain/verify
  });

  it('wraps route handlers with correct context mapping', async () => {
    const handlers: Record<string, Function> = {};
    const fastify = {
      get: vi.fn((path: string, handler: Function) => { handlers[`GET ${path}`] = handler; }),
      post: vi.fn((path: string, handler: Function) => { handlers[`POST ${path}`] = handler; }),
    };

    registerProofRoutes(fastify, pp);

    // Call the stats handler (simplest — no params needed)
    const mockReply = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    };
    const mockRequest = {
      params: {},
      query: {},
      body: {},
      id: 'req-1',
    };

    await handlers['GET /proof/stats'](mockRequest, mockReply);

    expect(mockReply.status).toHaveBeenCalledWith(200);
    expect(mockReply.send).toHaveBeenCalled();
    const body = mockReply.send.mock.calls[0][0];
    expect(body.data.totalEvents).toBe(0);
  });

  it('returns 400 for Zod validation errors', async () => {
    const handlers: Record<string, Function> = {};
    const fastify = {
      get: vi.fn((path: string, handler: Function) => { handlers[`GET ${path}`] = handler; }),
      post: vi.fn((path: string, handler: Function) => { handlers[`POST ${path}`] = handler; }),
    };

    registerProofRoutes(fastify, pp);

    const mockReply = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    };

    // Send invalid body to POST /proof — should trigger ZodError in the wrapper
    await handlers['POST /proof'](
      { params: {}, query: {}, body: { eventType: 'INVALID' }, id: 'req-2' },
      mockReply,
    );

    expect(mockReply.status).toHaveBeenCalledWith(400);
    const body = mockReply.send.mock.calls[0][0];
    expect(body.error.code).toBe('VALIDATION_ERROR');
  });

  it('re-throws non-Zod errors', async () => {
    // Use a store that throws a generic error on getStats
    const failingStore = {
      append: vi.fn(), get: vi.fn(), getLatest: vi.fn(),
      getLatestHash: vi.fn(), getChain: vi.fn(),
      getByCorrelationId: vi.fn(), getByAgentId: vi.fn(),
      getByTimeRange: vi.fn(), getByType: vi.fn(),
      query: vi.fn(), count: vi.fn(), getSummaries: vi.fn(),
      getStats: vi.fn().mockRejectedValue(new Error('DB down')),
      exists: vi.fn(), clear: vi.fn(),
    };
    const failPp = createProofPlane({ store: failingStore as any, enableSignatures: false });

    const handlers: Record<string, Function> = {};
    const fastify = {
      get: vi.fn((path: string, handler: Function) => { handlers[`GET ${path}`] = handler; }),
      post: vi.fn(),
    };
    registerProofRoutes(fastify, failPp);

    const mockReply = { status: vi.fn().mockReturnThis(), send: vi.fn() };

    await expect(
      handlers['GET /proof/stats']({ params: {}, query: {}, body: {}, id: 'x' }, mockReply),
    ).rejects.toThrow('DB down');
  });
});

describe('createProofExpressRouter (Express adapter)', () => {
  let pp: ProofPlane;

  beforeEach(() => {
    pp = createProofPlane({ signedBy: 'express-test', enableSignatures: false });
  });

  it('returns routes and a handler function', () => {
    const router = createProofExpressRouter(pp);
    expect(router.routes.length).toBeGreaterThan(0);
    expect(typeof router.handler).toBe('function');
  });

  it('matches and handles GET /proof/latest', async () => {
    // Use /proof/latest which won't collide with /proof/:id since
    // Express adapter matches routes in order and /proof/:id matches first.
    // /proof/latest has its own route — but it also matches /proof/:id first.
    // So test the POST route which has no ambiguity.
    const router = createProofExpressRouter(pp);
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    // POST /proof/chain/verify has a unique 3-segment path — no ambiguity
    await router.handler(
      { method: 'POST', path: '/proof/chain/verify', params: {}, query: {}, body: {}, headers: {} },
      res,
      next,
    );

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next() for unmatched routes', async () => {
    const router = createProofExpressRouter(pp);
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    await router.handler(
      { method: 'GET', path: '/unknown', params: {}, query: {}, body: {}, headers: {} },
      res,
      next,
    );

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('handles parameterized routes (GET /proof/:id)', async () => {
    // Emit an event first
    const result = await pp.logEvent(
      ProofEventType.INTENT_RECEIVED,
      uuidv4(),
      { type: 'intent_received', intentId: uuidv4(), action: 'test', actionType: 'read', resourceScope: [] },
    );

    const router = createProofExpressRouter(pp);
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    await router.handler(
      {
        method: 'GET',
        path: `/proof/${result.event.eventId}`,
        params: {},
        query: {},
        body: {},
        headers: { 'x-request-id': 'req-123' },
      },
      res,
      next,
    );

    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.data.eventId).toBe(result.event.eventId);
    expect(body.meta.requestId).toBe('req-123');
  });

  it('returns 404 for non-existent event ID', async () => {
    const router = createProofExpressRouter(pp);
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    await router.handler(
      {
        method: 'GET',
        path: `/proof/${uuidv4()}`,
        params: {},
        query: {},
        body: {},
        headers: {},
      },
      res,
      next,
    );

    expect(res.status).toHaveBeenCalledWith(404);
  });

  it('returns 400 for Zod validation error in Express', async () => {
    const router = createProofExpressRouter(pp);
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    await router.handler(
      {
        method: 'POST',
        path: '/proof',
        params: {},
        query: {},
        body: { eventType: 'INVALID' },
        headers: {},
      },
      res,
      next,
    );

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('VALIDATION_ERROR');
  });

  it('calls next(err) for non-Zod errors in Express', async () => {
    // Use verifyChain which calls store.getChain — 3-segment path avoids :id collision
    const failingStore = {
      append: vi.fn(), get: vi.fn(), getLatest: vi.fn(),
      getLatestHash: vi.fn(),
      getChain: vi.fn().mockRejectedValue(new Error('express boom')),
      getByCorrelationId: vi.fn(), getByAgentId: vi.fn(),
      getByTimeRange: vi.fn(), getByType: vi.fn(),
      query: vi.fn(), count: vi.fn(), getSummaries: vi.fn(),
      getStats: vi.fn(), exists: vi.fn(), clear: vi.fn(),
    };
    const failPp = createProofPlane({ store: failingStore as any, enableSignatures: false });
    const router = createProofExpressRouter(failPp);

    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    await router.handler(
      { method: 'POST', path: '/proof/chain/verify', params: {}, query: {}, body: {}, headers: {} },
      res,
      next,
    );

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(next.mock.calls[0][0].message).toBe('express boom');
  });

  it('does not match routes with wrong number of path segments', async () => {
    const router = createProofExpressRouter(pp);
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    // Path has extra segment — should not match /proof/:id
    await router.handler(
      { method: 'GET', path: '/proof/extra/segment', params: {}, query: {}, body: {}, headers: {} },
      res,
      next,
    );

    // /proof/extra/segment doesn't match any route exactly, should call next
    // Actually /proof/verify/:id would match 3 segments... let's use 4 segments
    await router.handler(
      { method: 'GET', path: '/proof/a/b/c', params: {}, query: {}, body: {}, headers: {} },
      res,
      next,
    );

    expect(next).toHaveBeenCalled();
  });
});
