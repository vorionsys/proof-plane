/**
 * Proof Plane API Routes
 *
 * Provides REST API endpoints for the Vorion audit system:
 * - POST /proof - Submit a proof event
 * - GET /proof/:id - Retrieve proof event by ID
 * - GET /proof/verify/:id - Verify a single proof event
 * - GET /proof/chain/:correlationId - Get event trace by correlation ID
 * - POST /proof/chain/verify - Verify chain integrity
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import { ProofEventType } from '@vorionsys/contracts';

import type { ProofPlane } from '../proof-plane/proof-plane.js';

/**
 * Zod schema for proof event submission
 */
const submitProofSchema = z.object({
  eventType: z.nativeEnum(ProofEventType),
  correlationId: z.string().uuid(),
  agentId: z.string().uuid().optional(),
  payload: z.record(z.string(), z.unknown()),
});

/**
 * Zod schema for event ID parameter
 */
const eventIdParamsSchema = z.object({
  id: z.string().uuid(),
});

/**
 * Zod schema for correlation ID parameter
 */
const correlationIdParamsSchema = z.object({
  correlationId: z.string().uuid(),
});

/**
 * Zod schema for chain verification request
 */
const verifyChainBodySchema = z.object({
  fromEventId: z.string().uuid().optional(),
  limit: z.number().int().min(1).max(10000).optional(),
});

/**
 * Zod schema for query options
 */
const queryOptionsSchema = z.object({
  limit: z.coerce.number().int().min(1).max(1000).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

/**
 * API response envelope
 */
interface ApiResponse<T> {
  data: T;
  meta: {
    requestId?: string;
    timestamp: string;
  };
}

/**
 * Error response envelope
 */
interface ApiError {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

/**
 * Route handler context - generic interface for Fastify-like frameworks
 */
interface RouteContext {
  request: {
    params?: unknown;
    query?: unknown;
    body?: unknown;
    id?: string;
  };
  reply: {
    status(code: number): RouteContext['reply'];
    send(data: unknown): void;
  };
}

/**
 * Route definition for registration
 */
export interface ProofRoute {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  handler: (ctx: RouteContext, proofPlane: ProofPlane) => Promise<void>;
  schema?: {
    params?: z.ZodSchema;
    query?: z.ZodSchema;
    body?: z.ZodSchema;
  };
}

/**
 * Create success response
 */
function success<T>(data: T, requestId?: string): ApiResponse<T> {
  return {
    data,
    meta: {
      requestId,
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Create error response
 */
function error(code: string, message: string, details?: unknown): ApiError {
  return {
    error: {
      code,
      message,
      details,
    },
  };
}

/**
 * Define all proof API routes
 */
export function createProofRoutes(proofPlane: ProofPlane): ProofRoute[] {
  return [
    // POST /proof - Submit a new proof event
    {
      method: 'POST',
      path: '/proof',
      schema: { body: submitProofSchema },
      handler: async (ctx) => {
        const body = submitProofSchema.parse(ctx.request.body ?? {});

        try {
          const result = await proofPlane.logEvent(
            body.eventType,
            body.correlationId,
            body.payload as unknown as Parameters<typeof proofPlane.logEvent>[2],
            body.agentId
          );

          ctx.reply.status(201).send(
            success(
              {
                eventId: result.event.eventId,
                eventType: result.event.eventType,
                correlationId: result.event.correlationId,
                eventHash: result.event.eventHash,
                previousHash: result.event.previousHash,
                occurredAt: result.event.occurredAt,
                recordedAt: result.event.recordedAt,
              },
              ctx.request.id
            )
          );
        } catch (err) {
          ctx.reply.status(500).send(
            error('EMIT_FAILED', 'Failed to emit proof event', {
              message: err instanceof Error ? err.message : String(err),
            })
          );
        }
      },
    },

    // GET /proof/:id - Get proof event by ID
    {
      method: 'GET',
      path: '/proof/:id',
      schema: { params: eventIdParamsSchema },
      handler: async (ctx) => {
        const params = eventIdParamsSchema.parse(ctx.request.params ?? {});

        const event = await proofPlane.getEvent(params.id);

        if (!event) {
          ctx.reply.status(404).send(
            error('EVENT_NOT_FOUND', `Proof event ${params.id} not found`)
          );
          return;
        }

        ctx.reply.status(200).send(success(event, ctx.request.id));
      },
    },

    // GET /proof/verify/:id - Verify a single proof event
    {
      method: 'GET',
      path: '/proof/verify/:id',
      schema: { params: eventIdParamsSchema },
      handler: async (ctx) => {
        const params = eventIdParamsSchema.parse(ctx.request.params ?? {});

        const event = await proofPlane.getEvent(params.id);

        if (!event) {
          ctx.reply.status(404).send(
            error('EVENT_NOT_FOUND', `Proof event ${params.id} not found`)
          );
          return;
        }

        // Verify hash integrity (dual-hash: SHA-256 + SHA3-256)
        const { computeEventHash, verifyEventHash3 } = await import('../events/hash-chain.js');
        const computedHash = await computeEventHash(event);
        const hashValid = computedHash === event.eventHash;
        const hash3Valid = verifyEventHash3(event);

        // Verify signature if present
        let signatureResult = null;
        if (event.signature && proofPlane.isSignatureVerificationEnabled()) {
          signatureResult = await proofPlane.verifyEventSignature(event);
        }

        ctx.reply.status(200).send(
          success(
            {
              eventId: event.eventId,
              verification: {
                hashValid,
                hash3Valid,
                computedHash,
                storedHash: event.eventHash,
                storedHash3: event.eventHash3 ?? null,
                signatureValid: signatureResult?.valid ?? null,
                signatureError: signatureResult?.error,
                signer: signatureResult?.signer,
                verifiedAt: new Date().toISOString(),
              },
            },
            ctx.request.id
          )
        );
      },
    },

    // GET /proof/chain/:correlationId - Get event trace by correlation ID
    {
      method: 'GET',
      path: '/proof/chain/:correlationId',
      schema: {
        params: correlationIdParamsSchema,
        query: queryOptionsSchema,
      },
      handler: async (ctx) => {
        const params = correlationIdParamsSchema.parse(ctx.request.params ?? {});
        const query = queryOptionsSchema.parse(ctx.request.query ?? {});

        const events = await proofPlane.getTrace(params.correlationId);

        if (events.length === 0) {
          ctx.reply.status(404).send(
            error('TRACE_NOT_FOUND', `No events found for correlation ${params.correlationId}`)
          );
          return;
        }

        // Apply pagination
        const offset = query.offset ?? 0;
        const limit = query.limit ?? 100;
        const paginatedEvents = events.slice(offset, offset + limit);

        ctx.reply.status(200).send(
          success(
            {
              correlationId: params.correlationId,
              events: paginatedEvents,
              total: events.length,
              pagination: {
                offset,
                limit,
                hasMore: offset + limit < events.length,
              },
            },
            ctx.request.id
          )
        );
      },
    },

    // POST /proof/chain/verify - Verify chain integrity
    {
      method: 'POST',
      path: '/proof/chain/verify',
      schema: { body: verifyChainBodySchema },
      handler: async (ctx) => {
        const body = verifyChainBodySchema.parse(ctx.request.body ?? {});

        const chainResult = await proofPlane.verifyChain(body.fromEventId, body.limit);

        // Optionally verify signatures
        let signaturesResult = null;
        if (proofPlane.isSignatureVerificationEnabled()) {
          const fullResult = await proofPlane.verifyChainAndSignatures(
            body.fromEventId,
            body.limit
          );
          signaturesResult = fullResult.signatures;
        }

        ctx.reply.status(200).send(
          success(
            {
              chain: {
                valid: chainResult.valid,
                verifiedCount: chainResult.verifiedCount,
                totalEvents: chainResult.totalEvents,
                firstEventId: chainResult.firstEventId,
                lastEventId: chainResult.lastEventId,
                brokenAtEventId: chainResult.brokenAtEventId,
                brokenAtIndex: chainResult.brokenAtIndex,
                error: chainResult.error,
              },
              signatures: signaturesResult
                ? {
                    totalEvents: signaturesResult.totalEvents,
                    validCount: signaturesResult.validCount,
                    invalidCount: signaturesResult.invalidCount,
                    unsignedCount: signaturesResult.unsignedCount,
                    success: signaturesResult.success,
                  }
                : null,
              fullyVerified: chainResult.valid && (signaturesResult?.success ?? true),
              verifiedAt: new Date().toISOString(),
            },
            ctx.request.id
          )
        );
      },
    },

    // GET /proof/stats - Get event statistics
    {
      method: 'GET',
      path: '/proof/stats',
      handler: async (ctx) => {
        const stats = await proofPlane.getStats();

        ctx.reply.status(200).send(
          success(
            {
              totalEvents: stats.totalEvents,
              eventsByType: stats.byType,
              eventsByAgent: stats.byAgent,
              oldestEvent: stats.oldestEvent,
              newestEvent: stats.newestEvent,
              shadowModeStats: stats.byShadowMode,
            },
            ctx.request.id
          )
        );
      },
    },

    // GET /proof/latest - Get most recent event
    {
      method: 'GET',
      path: '/proof/latest',
      handler: async (ctx) => {
        const event = await proofPlane.getLatestEvent();

        if (!event) {
          ctx.reply.status(404).send(
            error('NO_EVENTS', 'No proof events recorded yet')
          );
          return;
        }

        ctx.reply.status(200).send(success(event, ctx.request.id));
      },
    },
  ];
}

/**
 * Fastify plugin registration helper
 *
 * Usage with Fastify:
 * ```typescript
 * import Fastify from 'fastify';
 * import { createProofPlane } from '@vorionsys/proof-plane';
 * import { registerProofRoutes } from '@vorionsys/proof-plane/api';
 *
 * const app = Fastify();
 * const proofPlane = createProofPlane({ signedBy: 'my-service' });
 *
 * await app.register(async (instance) => {
 *   registerProofRoutes(instance, proofPlane);
 * }, { prefix: '/v1' });
 * ```
 */
interface FastifyLikeRequest {
  params: Record<string, string>;
  query: Record<string, string>;
  body: unknown;
  id: string;
}

interface FastifyLikeReply {
  status(code: number): FastifyLikeReply;
  send(data: unknown): void;
}

export function registerProofRoutes(
  fastify: {
    get: (path: string, handler: (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>) => void;
    post: (path: string, handler: (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>) => void;
  },
  proofPlane: ProofPlane
): void {
  const routes = createProofRoutes(proofPlane);

  for (const route of routes) {
    const handler = async (request: FastifyLikeRequest, reply: FastifyLikeReply) => {
      const ctx: RouteContext = {
        request: {
          params: request.params,
          query: request.query,
          body: request.body,
          id: request.id,
        },
        reply: {
          status(code: number) {
            reply.status(code);
            return this;
          },
          send(data: unknown) {
            reply.send(data);
          },
        },
      };

      try {
        await route.handler(ctx, proofPlane);
      } catch (err) {
        if (err instanceof z.ZodError) {
          reply.status(400).send(
            error('VALIDATION_ERROR', 'Request validation failed', err.errors)
          );
          return;
        }
        throw err;
      }
    };

    if (route.method === 'GET') {
      fastify.get(route.path, handler);
    } else if (route.method === 'POST') {
      fastify.post(route.path, handler);
    }
  }
}

/**
 * Express middleware adapter
 *
 * Usage with Express:
 * ```typescript
 * import express from 'express';
 * import { createProofPlane } from '@vorionsys/proof-plane';
 * import { createProofExpressRouter } from '@vorionsys/proof-plane/api';
 *
 * const app = express();
 * const proofPlane = createProofPlane({ signedBy: 'my-service' });
 *
 * app.use('/v1', createProofExpressRouter(proofPlane));
 * ```
 */
export function createProofExpressRouter(proofPlane: ProofPlane): {
  routes: ProofRoute[];
  handler: (req: any, res: any, next: any) => Promise<void>;
} {
  const routes = createProofRoutes(proofPlane);

  const handler = async (req: any, res: any, next: any) => {
    const matchedRoute = routes.find(
      (r) =>
        r.method === req.method &&
        matchPath(r.path, req.path)
    );

    if (!matchedRoute) {
      next();
      return;
    }

    const ctx: RouteContext = {
      request: {
        params: extractParams(matchedRoute.path, req.path),
        query: req.query,
        body: req.body,
        id: req.headers['x-request-id'],
      },
      reply: {
        status(code: number) {
          res.status(code);
          return this;
        },
        send(data: unknown) {
          res.json(data);
        },
      },
    };

    try {
      await matchedRoute.handler(ctx, proofPlane);
    } catch (err) {
      if (err instanceof z.ZodError) {
        res.status(400).json(
          error('VALIDATION_ERROR', 'Request validation failed', err.errors)
        );
        return;
      }
      next(err);
    }
  };

  return { routes, handler };
}

/**
 * Simple path matching for Express adapter
 */
function matchPath(pattern: string, path: string): boolean {
  const patternParts = pattern.split('/');
  const pathParts = path.split('/');

  if (patternParts.length !== pathParts.length) {
    return false;
  }

  return patternParts.every((part, i) => {
    if (part.startsWith(':')) {
      return true; // Parameter matches anything
    }
    return part === pathParts[i];
  });
}

/**
 * Extract parameters from path
 */
function extractParams(
  pattern: string,
  path: string
): Record<string, string> {
  const params: Record<string, string> = {};
  const patternParts = pattern.split('/');
  const pathParts = path.split('/');

  patternParts.forEach((part, i) => {
    if (part.startsWith(':')) {
      const paramName = part.slice(1);
      params[paramName] = pathParts[i];
    }
  });

  return params;
}
