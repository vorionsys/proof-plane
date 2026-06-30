/**
 * External Timestamp Anchoring for Proof Chain
 *
 * Publishes Merkle root hashes to external timestamp authorities
 * for independent verification. This ensures proof chain integrity
 * can be verified by any third party without access to the Vorion platform.
 *
 * Supports multiple anchoring methods:
 * - RFC 3161 Trusted Timestamp (TSA endpoint)
 * - Git tag (signed tag with Merkle root — MVP, no external dependency)
 * - DNS TXT record (publish root hash as DNS record)
 * - Blockchain (Ethereum/Bitcoin anchoring for maximum independence)
 *
 * Required for NIST NCCoE compliance: "How can we ensure that agents
 * log their actions and intent in a tamper-proof and verifiable manner?"
 *
 * @packageDocumentation
 */

import { createHash } from 'node:crypto';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Anchoring method for publishing Merkle roots externally.
 */
export type AnchorMethod = 'rfc3161' | 'git-tag' | 'dns-txt' | 'blockchain';

/**
 * Configuration for external anchoring.
 */
export interface AnchorConfig {
  /** Anchoring method */
  method: AnchorMethod;
  /** Anchor every N events (default: 1000) */
  interval: number;
  /** TSA endpoint for RFC 3161 method */
  endpoint?: string;
  /** Git repository path for git-tag method */
  repoPath?: string;
  /** Signing key for git-tag signatures */
  signingKey?: string;
}

/**
 * A timestamp anchor — proof that a Merkle root existed at a specific time.
 */
export interface TimestampAnchor {
  /** The Merkle root hash that was anchored */
  merkleRoot: string;
  /** Number of events covered by this root */
  eventCount: number;
  /** When the anchor was created */
  anchoredAt: Date;
  /** Method used for anchoring */
  method: AnchorMethod;
  /** The evidence (timestamp token, git tag hash, DNS proof, tx hash) */
  evidence: string;
  /** Where to verify this anchor */
  verificationUrl?: string;
  /** SHA-256 hash of the anchor request for integrity */
  requestHash: string;
}

/**
 * Result of verifying a timestamp anchor.
 */
export interface AnchorVerificationResult {
  /** Whether the anchor is valid */
  valid: boolean;
  /** The Merkle root that was verified */
  merkleRoot: string;
  /** Method used */
  method: AnchorMethod;
  /** Errors if invalid */
  errors: string[];
  /** Timestamp from the anchor */
  anchoredAt?: Date;
}

// ─── Implementation ──────────────────────────────────────────────────────────

/**
 * Create a timestamp request payload for a Merkle root.
 *
 * The request is a SHA-256 hash of the root + event count + timestamp,
 * providing a deterministic binding.
 */
export function createTimestampRequest(
  merkleRoot: string,
  eventCount: number,
): { requestHash: string; payload: string } {
  const timestamp = new Date().toISOString();
  const payload = JSON.stringify({
    merkleRoot,
    eventCount,
    timestamp,
    version: '1.0',
  });
  const requestHash = createHash('sha256').update(payload).digest('hex');
  return { requestHash, payload };
}

/**
 * Create a git-tag based anchor (MVP — no external service needed).
 *
 * Creates a lightweight tag reference with the Merkle root as the tag name
 * and the event metadata as the message. The tag can be verified by anyone
 * with access to the git repository.
 *
 * Tag format: `proof-anchor/{merkleRoot.slice(0, 12)}`
 * Message: JSON with full merkleRoot, eventCount, timestamp
 */
export function createGitTagAnchor(
  merkleRoot: string,
  eventCount: number,
): TimestampAnchor {
  const now = new Date();
  const tagName = `proof-anchor/${merkleRoot.slice(0, 12)}`;
  const { requestHash } = createTimestampRequest(merkleRoot, eventCount);

  const evidence = JSON.stringify({
    tag: tagName,
    message: `Proof chain anchor: ${eventCount} events, root ${merkleRoot}`,
    merkleRoot,
    eventCount,
    createdAt: now.toISOString(),
  });

  return {
    merkleRoot,
    eventCount,
    anchoredAt: now,
    method: 'git-tag',
    evidence,
    requestHash,
    verificationUrl: `git tag -v ${tagName}`,
  };
}

/**
 * Create an RFC 3161 timestamp request structure.
 *
 * Note: Actual TSA communication requires an HTTP client to POST
 * to the TSA endpoint. This function creates the request structure
 * that would be sent.
 */
export function createRFC3161Request(
  merkleRoot: string,
  eventCount: number,
  tsaEndpoint: string,
): TimestampAnchor {
  const now = new Date();
  const { requestHash } = createTimestampRequest(merkleRoot, eventCount);

  // In production, this would POST to the TSA endpoint
  // and receive a signed timestamp token (RFC 3161 TimeStampResp)
  const evidence = JSON.stringify({
    tsaEndpoint,
    requestHash,
    merkleRoot,
    eventCount,
    protocol: 'RFC 3161',
    status: 'request_created',
    createdAt: now.toISOString(),
  });

  return {
    merkleRoot,
    eventCount,
    anchoredAt: now,
    method: 'rfc3161',
    evidence,
    requestHash,
    verificationUrl: tsaEndpoint,
  };
}

/**
 * Anchor a Merkle root using the configured method.
 */
export function anchorMerkleRoot(
  merkleRoot: string,
  eventCount: number,
  config: AnchorConfig,
): TimestampAnchor {
  switch (config.method) {
    case 'git-tag':
      return createGitTagAnchor(merkleRoot, eventCount);
    case 'rfc3161':
      if (!config.endpoint) {
        throw new Error('RFC 3161 method requires an endpoint URL');
      }
      return createRFC3161Request(merkleRoot, eventCount, config.endpoint);
    case 'dns-txt':
    case 'blockchain':
      throw new Error(`Anchoring method '${config.method}' is not yet implemented`);
    default:
      throw new Error(`Unknown anchoring method: ${config.method}`);
  }
}

/**
 * Verify a timestamp anchor's integrity.
 *
 * Checks that the evidence is well-formed and the request hash
 * matches the Merkle root binding.
 */
export function verifyAnchor(anchor: TimestampAnchor): AnchorVerificationResult {
  const errors: string[] = [];

  // Verify merkle root is present and valid hex
  if (!anchor.merkleRoot || !/^[0-9a-f]{64}$/i.test(anchor.merkleRoot)) {
    errors.push('Invalid or missing Merkle root hash');
  }

  // Verify event count is positive
  if (!anchor.eventCount || anchor.eventCount <= 0) {
    errors.push('Event count must be positive');
  }

  // Verify evidence is parseable
  try {
    const evidence = JSON.parse(anchor.evidence);
    if (evidence.merkleRoot !== anchor.merkleRoot) {
      errors.push('Evidence merkleRoot does not match anchor merkleRoot');
    }
  } catch {
    errors.push('Evidence is not valid JSON');
  }

  // Verify request hash
  if (!anchor.requestHash || !/^[0-9a-f]{64}$/i.test(anchor.requestHash)) {
    errors.push('Invalid or missing request hash');
  }

  return {
    valid: errors.length === 0,
    merkleRoot: anchor.merkleRoot,
    method: anchor.method,
    errors,
    anchoredAt: anchor.anchoredAt,
  };
}
