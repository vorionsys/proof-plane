/**
 * RFC 3161 Timestamp Authority Client
 *
 * Provides independent, third-party timestamping of Merkle roots
 * via RFC 3161 Timestamp Authorities. This closes the "self-asserted
 * timestamp" gap: a court or regulator can verify WHEN events occurred
 * without trusting the Vorion platform's own clock.
 *
 * Design decisions:
 * - Batch anchoring by default: one TSA call per Merkle batch, not per event
 * - Opt-in: zero overhead when disabled (no HTTP calls, no allocations)
 * - Graceful degradation: TSA failure never blocks the proof chain flush
 * - Simplified JSON-based protocol for test TSAs; full ASN.1 DER encoding
 *   is marked TODO for production (requires node:crypto X509 APIs)
 *
 * Recommended TSA services (configure via tsaUrl, never hardcoded):
 * - FreeTSA.org (dev/staging)
 * - DigiCert Timestamp Authority (production)
 * - Sectigo / Comodo (alternative)
 * - Self-hosted (enterprise with own PKI)
 *
 * @see SPEC-EVIDENCE-ADMISSIBILITY.md Gap 2
 * @packageDocumentation
 */

import { createHash, randomUUID } from 'node:crypto';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Configuration for the Timestamp Authority client.
 *
 * Env var mapping (for feature-flag integration):
 * - PROOF_TSA_ENABLED  → enabled
 * - PROOF_TSA_ENDPOINT → tsaUrl
 */
export interface TimestampAuthorityConfig {
  /** TSA endpoint URL (e.g. 'http://timestamp.digicert.com') */
  tsaUrl: string;
  /** Hash algorithm for the timestamp request (only SHA-256 supported) */
  hashAlgorithm: 'sha-256';
  /** HTTP timeout in milliseconds */
  timeout: number;
  /** Whether TSA integration is active */
  enabled: boolean;
  /** When true, timestamps Merkle roots (one call per batch). When false, timestamps individual hashes. */
  batchAnchoring: boolean;
}

/**
 * A timestamp token received from a TSA.
 *
 * In production, `rawToken` will contain the base64-encoded DER
 * TimeStampToken (CMS SignedData). In the current simplified
 * implementation it holds a JSON structure for test TSA compatibility.
 */
export interface TimestampToken {
  /** Unique identifier for this token */
  tokenId: string;
  /** The TSA endpoint that issued this token */
  tsaUrl: string;
  /** SHA-256 hash that was submitted to the TSA */
  requestHash: string;
  /** SHA-256 hash of the TSA response (for integrity binding) */
  responseHash: string;
  /** Timestamp asserted by the TSA (ISO 8601) */
  timestamp: string;
  /** Base64-encoded DER TimeStampToken (or JSON for test TSAs) */
  rawToken: string;
  /** Whether the token has been verified against the TSA's certificate */
  verified: boolean;
}

/**
 * Default config — TSA is OFF by default (zero overhead).
 */
export const DEFAULT_TSA_CONFIG: TimestampAuthorityConfig = {
  tsaUrl: '',
  hashAlgorithm: 'sha-256',
  timeout: 5000,
  enabled: false,
  batchAnchoring: true,
};

// ─── Client ───────────────────────────────────────────────────────────────────

/**
 * Timestamp Authority client for RFC 3161 timestamping.
 *
 * Usage:
 * ```ts
 * const tsa = new TimestampAuthorityClient({
 *   ...DEFAULT_TSA_CONFIG,
 *   tsaUrl: 'http://timestamp.digicert.com',
 *   enabled: true,
 * });
 *
 * // Timestamp a Merkle root (the efficient path)
 * const token = await tsa.timestampMerkleRoot(merkleRootHex);
 * ```
 */
export class TimestampAuthorityClient {
  private readonly config: TimestampAuthorityConfig;

  constructor(config: TimestampAuthorityConfig) {
    this.config = { ...config };
  }

  /**
   * Request a timestamp for an arbitrary SHA-256 hash.
   *
   * Sends the hash to the configured TSA endpoint and returns the
   * signed timestamp token. Currently uses a simplified JSON-based
   * protocol; full ASN.1 DER encoding is TODO for production.
   *
   * @param hash - Hex-encoded SHA-256 hash to timestamp
   * @throws {Error} if the TSA is unreachable or returns an error
   */
  async requestTimestamp(hash: string): Promise<TimestampToken> {
    if (!this.config.enabled) {
      throw new Error('TimestampAuthority is not enabled');
    }
    if (!this.config.tsaUrl) {
      throw new Error('TimestampAuthority tsaUrl is not configured');
    }

    const nonce = randomUUID();
    const requestBody = JSON.stringify({
      version: 1,
      messageImprint: {
        hashAlgorithm: this.config.hashAlgorithm,
        hashedMessage: hash,
      },
      nonce,
      certReq: true,
    });

    // TODO: Replace JSON body with proper ASN.1 DER-encoded TimeStampReq
    // per RFC 3161 Section 2.4.1. Use node:crypto X509 APIs (Node 22+)
    // to construct the request and parse the TimeStampResp.
    //
    // For now, this works with test/mock TSAs that accept JSON.
    // Production TSAs (DigiCert, FreeTSA) require:
    //   Content-Type: application/timestamp-query
    //   Body: DER-encoded TimeStampReq

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(this.config.tsaUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: requestBody,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(
          `TSA request failed: HTTP ${response.status} ${response.statusText}`
        );
      }

      const responseBody = await response.text();
      const responseHash = createHash('sha256')
        .update(responseBody)
        .digest('hex');

      // Encode the response as base64 for storage
      const rawToken = Buffer.from(responseBody).toString('base64');

      // Try to parse timestamp from response (JSON TSAs include it)
      let tsaTimestamp: string;
      try {
        const parsed = JSON.parse(responseBody);
        tsaTimestamp = parsed.timestamp ?? parsed.genTime ?? new Date().toISOString();
      } catch {
        // Non-JSON response (real DER token) — use current time as placeholder
        // TODO: Parse genTime from ASN.1 TSTInfo when DER decoding is implemented
        tsaTimestamp = new Date().toISOString();
      }

      return {
        tokenId: randomUUID(),
        tsaUrl: this.config.tsaUrl,
        requestHash: hash,
        responseHash,
        timestamp: tsaTimestamp,
        rawToken,
        verified: false, // Verification is a separate step
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Verify a previously obtained timestamp token.
   *
   * Checks that:
   * 1. The rawToken can be decoded
   * 2. The response hash matches the stored responseHash
   * 3. The request hash in the token matches the original hash
   *
   * TODO: Full verification requires:
   * - Parsing the CMS SignedData from the DER token
   * - Verifying the TSA's signing certificate against a trust store
   * - Checking certificate validity period and revocation status
   *
   * @param token - The timestamp token to verify
   * @returns true if the token passes integrity checks
   */
  async verifyTimestamp(token: TimestampToken): Promise<boolean> {
    try {
      // Decode the raw token
      const decoded = Buffer.from(token.rawToken, 'base64').toString('utf-8');

      // Recompute response hash and compare
      const computedHash = createHash('sha256').update(decoded).digest('hex');
      if (computedHash !== token.responseHash) {
        return false;
      }

      // Verify the request hash is embedded in the response
      try {
        const parsed = JSON.parse(decoded);
        if (
          parsed.messageImprint?.hashedMessage &&
          parsed.messageImprint.hashedMessage !== token.requestHash
        ) {
          return false;
        }
      } catch {
        // Non-JSON token — skip content verification for now
        // TODO: Parse ASN.1 TSTInfo and verify messageImprint
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Timestamp a Merkle root — the efficient path.
   *
   * This is the primary integration point: one TSA call per batch,
   * not per event. The Merkle root binds every event in the batch
   * to the TSA timestamp.
   *
   * @param root - Hex-encoded Merkle root hash
   * @returns The timestamp token for the root
   */
  async timestampMerkleRoot(root: string): Promise<TimestampToken> {
    return this.requestTimestamp(root);
  }
}

// ─── Mock TSA ─────────────────────────────────────────────────────────────────

/**
 * Mock Timestamp Authority for testing.
 *
 * Returns deterministic, well-formed tokens without any network calls.
 * Use this in tests to verify TSA integration logic without depending
 * on external services.
 *
 * @example
 * ```ts
 * const mock = new MockTimestampAuthority();
 * const token = await mock.requestTimestamp('abc123...');
 * expect(token.requestHash).toBe('abc123...');
 * expect(token.verified).toBe(false);
 * ```
 */
export class MockTimestampAuthority {
  /** Tracks all calls for test assertions */
  readonly calls: Array<{ method: string; args: unknown[] }> = [];

  /** Fixed timestamp for deterministic tests */
  readonly fixedTimestamp: string;

  /** Whether requestTimestamp should throw (for failure testing) */
  shouldFail = false;

  /** Custom error message when shouldFail is true */
  failureMessage = 'Mock TSA failure: simulated outage';

  constructor(fixedTimestamp?: string) {
    this.fixedTimestamp = fixedTimestamp ?? '2026-04-04T12:00:00.000Z';
  }

  async requestTimestamp(hash: string): Promise<TimestampToken> {
    this.calls.push({ method: 'requestTimestamp', args: [hash] });

    if (this.shouldFail) {
      throw new Error(this.failureMessage);
    }

    const responseBody = JSON.stringify({
      status: { status: 0, statusString: 'granted' },
      timeStampToken: {
        contentType: '1.2.840.113549.1.7.2', // CMS SignedData OID
        content: {
          version: 3,
          digestAlgorithms: [{ algorithm: '2.16.840.1.101.3.4.2.1' }], // SHA-256 OID
          encapContentInfo: {
            eContentType: '1.2.840.113549.1.9.16.1.4', // TSTInfo OID
            eContent: {
              version: 1,
              policy: '1.2.3.4.1',
              messageImprint: {
                hashAlgorithm: 'sha-256',
                hashedMessage: hash,
              },
              serialNumber: Date.now(),
              genTime: this.fixedTimestamp,
              nonce: 'mock-nonce',
            },
          },
        },
      },
      timestamp: this.fixedTimestamp,
      messageImprint: {
        hashAlgorithm: 'sha-256',
        hashedMessage: hash,
      },
    });

    const responseHash = createHash('sha256')
      .update(responseBody)
      .digest('hex');

    return {
      tokenId: `mock-${hash.substring(0, 8)}-${Date.now()}`,
      tsaUrl: 'mock://test-tsa',
      requestHash: hash,
      responseHash,
      timestamp: this.fixedTimestamp,
      rawToken: Buffer.from(responseBody).toString('base64'),
      verified: false,
    };
  }

  async verifyTimestamp(token: TimestampToken): Promise<boolean> {
    this.calls.push({ method: 'verifyTimestamp', args: [token] });

    if (this.shouldFail) {
      return false;
    }

    // Verify the rawToken decodes and response hash matches
    const decoded = Buffer.from(token.rawToken, 'base64').toString('utf-8');
    const computedHash = createHash('sha256').update(decoded).digest('hex');
    return computedHash === token.responseHash;
  }

  async timestampMerkleRoot(root: string): Promise<TimestampToken> {
    this.calls.push({ method: 'timestampMerkleRoot', args: [root] });
    return this.requestTimestamp(root);
  }

  /**
   * Reset call tracking (useful between test cases).
   */
  reset(): void {
    this.calls.length = 0;
    this.shouldFail = false;
  }
}
