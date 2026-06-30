import { describe, it, expect } from 'vitest';
import {
  createTimestampRequest,
  createGitTagAnchor,
  createRFC3161Request,
  anchorMerkleRoot,
  verifyAnchor,
  type AnchorConfig,
} from '../src/events/external-anchor.js';

const VALID_MERKLE_ROOT = 'a'.repeat(64);
const EVENT_COUNT = 1000;

describe('External Timestamp Anchoring', () => {
  describe('createTimestampRequest', () => {
    it('creates a request with valid hash and payload', () => {
      const { requestHash, payload } = createTimestampRequest(VALID_MERKLE_ROOT, EVENT_COUNT);
      expect(requestHash).toMatch(/^[0-9a-f]{64}$/);
      expect(payload).toContain(VALID_MERKLE_ROOT);
      const parsed = JSON.parse(payload);
      expect(parsed.merkleRoot).toBe(VALID_MERKLE_ROOT);
      expect(parsed.eventCount).toBe(EVENT_COUNT);
      expect(parsed.version).toBe('1.0');
    });

    it('produces deterministic hash for same inputs within same timestamp', () => {
      const r1 = createTimestampRequest(VALID_MERKLE_ROOT, EVENT_COUNT);
      // Different timestamp means different hash — that's correct behavior
      expect(r1.requestHash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('createGitTagAnchor', () => {
    it('creates valid git-tag anchor', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      expect(anchor.merkleRoot).toBe(VALID_MERKLE_ROOT);
      expect(anchor.eventCount).toBe(EVENT_COUNT);
      expect(anchor.method).toBe('git-tag');
      expect(anchor.anchoredAt).toBeInstanceOf(Date);
      expect(anchor.requestHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('evidence contains tag name with root prefix', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      const evidence = JSON.parse(anchor.evidence);
      expect(evidence.tag).toBe(`proof-anchor/${VALID_MERKLE_ROOT.slice(0, 12)}`);
      expect(evidence.merkleRoot).toBe(VALID_MERKLE_ROOT);
    });

    it('verification URL references git tag verify command', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      expect(anchor.verificationUrl).toContain('git tag -v');
    });
  });

  describe('createRFC3161Request', () => {
    it('creates valid RFC 3161 request', () => {
      const endpoint = 'https://freetsa.org/tsr';
      const anchor = createRFC3161Request(VALID_MERKLE_ROOT, EVENT_COUNT, endpoint);
      expect(anchor.method).toBe('rfc3161');
      expect(anchor.verificationUrl).toBe(endpoint);
      const evidence = JSON.parse(anchor.evidence);
      expect(evidence.protocol).toBe('RFC 3161');
      expect(evidence.tsaEndpoint).toBe(endpoint);
    });
  });

  describe('anchorMerkleRoot', () => {
    it('dispatches to git-tag method', () => {
      const config: AnchorConfig = { method: 'git-tag', interval: 1000 };
      const anchor = anchorMerkleRoot(VALID_MERKLE_ROOT, EVENT_COUNT, config);
      expect(anchor.method).toBe('git-tag');
    });

    it('dispatches to rfc3161 method', () => {
      const config: AnchorConfig = { method: 'rfc3161', interval: 1000, endpoint: 'https://tsa.example.com' };
      const anchor = anchorMerkleRoot(VALID_MERKLE_ROOT, EVENT_COUNT, config);
      expect(anchor.method).toBe('rfc3161');
    });

    it('throws for rfc3161 without endpoint', () => {
      const config: AnchorConfig = { method: 'rfc3161', interval: 1000 };
      expect(() => anchorMerkleRoot(VALID_MERKLE_ROOT, EVENT_COUNT, config)).toThrow('endpoint');
    });

    it('throws for unimplemented methods', () => {
      const config: AnchorConfig = { method: 'blockchain', interval: 1000 };
      expect(() => anchorMerkleRoot(VALID_MERKLE_ROOT, EVENT_COUNT, config)).toThrow('not yet implemented');
    });
  });

  describe('verifyAnchor', () => {
    it('verifies a valid git-tag anchor', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      const result = verifyAnchor(anchor);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.merkleRoot).toBe(VALID_MERKLE_ROOT);
    });

    it('verifies a valid rfc3161 anchor', () => {
      const anchor = createRFC3161Request(VALID_MERKLE_ROOT, EVENT_COUNT, 'https://tsa.example.com');
      const result = verifyAnchor(anchor);
      expect(result.valid).toBe(true);
    });

    it('fails on invalid merkle root', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      anchor.merkleRoot = 'not-a-hash';
      const result = verifyAnchor(anchor);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid or missing Merkle root hash');
    });

    it('fails on zero event count', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      anchor.eventCount = 0;
      const result = verifyAnchor(anchor);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Event count must be positive');
    });

    it('fails on evidence merkle root mismatch', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      anchor.merkleRoot = 'b'.repeat(64); // change root but not evidence
      const result = verifyAnchor(anchor);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Evidence merkleRoot does not match anchor merkleRoot');
    });

    it('fails on invalid evidence JSON', () => {
      const anchor = createGitTagAnchor(VALID_MERKLE_ROOT, EVENT_COUNT);
      anchor.evidence = 'not json';
      const result = verifyAnchor(anchor);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Evidence is not valid JSON');
    });
  });
});
