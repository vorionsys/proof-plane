import { describe, it, expect, beforeEach } from 'vitest';
import {
  TimestampAuthorityClient,
  MockTimestampAuthority,
  DEFAULT_TSA_CONFIG,
  type TimestampAuthorityConfig,
  type TimestampToken,
} from '../src/events/timestamp-authority.js';

const VALID_MERKLE_ROOT = 'a'.repeat(64);

describe('TimestampAuthority', () => {
  describe('DEFAULT_TSA_CONFIG', () => {
    it('is disabled by default', () => {
      expect(DEFAULT_TSA_CONFIG.enabled).toBe(false);
    });

    it('uses sha-256', () => {
      expect(DEFAULT_TSA_CONFIG.hashAlgorithm).toBe('sha-256');
    });

    it('has 5000ms timeout', () => {
      expect(DEFAULT_TSA_CONFIG.timeout).toBe(5000);
    });

    it('uses batch anchoring by default', () => {
      expect(DEFAULT_TSA_CONFIG.batchAnchoring).toBe(true);
    });
  });

  describe('TimestampAuthorityClient', () => {
    it('throws when not enabled', async () => {
      const client = new TimestampAuthorityClient({
        ...DEFAULT_TSA_CONFIG,
        enabled: false,
        tsaUrl: 'http://example.com',
      });

      await expect(client.requestTimestamp(VALID_MERKLE_ROOT)).rejects.toThrow(
        'not enabled'
      );
    });

    it('throws when tsaUrl is empty', async () => {
      const client = new TimestampAuthorityClient({
        ...DEFAULT_TSA_CONFIG,
        enabled: true,
        tsaUrl: '',
      });

      await expect(client.requestTimestamp(VALID_MERKLE_ROOT)).rejects.toThrow(
        'tsaUrl is not configured'
      );
    });

    it('timestampMerkleRoot delegates to requestTimestamp', async () => {
      // We can't test a real TSA call without a server, but we can verify
      // the method exists and calls through. Use MockTimestampAuthority for
      // functional testing instead.
      const client = new TimestampAuthorityClient({
        ...DEFAULT_TSA_CONFIG,
        enabled: false,
      });

      await expect(client.timestampMerkleRoot(VALID_MERKLE_ROOT)).rejects.toThrow(
        'not enabled'
      );
    });
  });

  describe('MockTimestampAuthority', () => {
    let mock: MockTimestampAuthority;

    beforeEach(() => {
      mock = new MockTimestampAuthority();
    });

    it('returns a valid token for requestTimestamp', async () => {
      const token = await mock.requestTimestamp(VALID_MERKLE_ROOT);

      expect(token.tokenId).toBeDefined();
      expect(token.tokenId).toContain('mock-');
      expect(token.tsaUrl).toBe('mock://test-tsa');
      expect(token.requestHash).toBe(VALID_MERKLE_ROOT);
      expect(token.responseHash).toMatch(/^[0-9a-f]{64}$/);
      expect(token.timestamp).toBe('2026-04-04T12:00:00.000Z');
      expect(token.rawToken).toBeDefined();
      expect(token.verified).toBe(false);
    });

    it('uses custom fixed timestamp', async () => {
      const custom = new MockTimestampAuthority('2025-01-01T00:00:00.000Z');
      const token = await custom.requestTimestamp(VALID_MERKLE_ROOT);
      expect(token.timestamp).toBe('2025-01-01T00:00:00.000Z');
    });

    it('rawToken decodes to valid JSON', async () => {
      const token = await mock.requestTimestamp(VALID_MERKLE_ROOT);
      const decoded = Buffer.from(token.rawToken, 'base64').toString('utf-8');
      const parsed = JSON.parse(decoded);

      expect(parsed.status.statusString).toBe('granted');
      expect(parsed.messageImprint.hashedMessage).toBe(VALID_MERKLE_ROOT);
      expect(parsed.timestamp).toBe('2026-04-04T12:00:00.000Z');
    });

    it('timestampMerkleRoot produces correct hash in token', async () => {
      const token = await mock.timestampMerkleRoot(VALID_MERKLE_ROOT);
      expect(token.requestHash).toBe(VALID_MERKLE_ROOT);

      // Decode and verify the hash is embedded
      const decoded = Buffer.from(token.rawToken, 'base64').toString('utf-8');
      const parsed = JSON.parse(decoded);
      expect(parsed.messageImprint.hashedMessage).toBe(VALID_MERKLE_ROOT);
    });

    it('tracks calls for assertion', async () => {
      expect(mock.calls).toHaveLength(0);

      await mock.requestTimestamp('hash1');
      await mock.timestampMerkleRoot('hash2');

      expect(mock.calls).toHaveLength(3); // timestampMerkleRoot calls requestTimestamp too
      expect(mock.calls[0]).toEqual({
        method: 'requestTimestamp',
        args: ['hash1'],
      });
      expect(mock.calls[1]).toEqual({
        method: 'timestampMerkleRoot',
        args: ['hash2'],
      });
    });

    it('verifyTimestamp returns true for valid token', async () => {
      const token = await mock.requestTimestamp(VALID_MERKLE_ROOT);
      const result = await mock.verifyTimestamp(token);
      expect(result).toBe(true);
    });

    it('verifyTimestamp returns false when shouldFail is set', async () => {
      const token = await mock.requestTimestamp(VALID_MERKLE_ROOT);
      mock.shouldFail = true;
      const result = await mock.verifyTimestamp(token);
      expect(result).toBe(false);
    });

    it('verifyTimestamp detects tampered token', async () => {
      const token = await mock.requestTimestamp(VALID_MERKLE_ROOT);
      // Tamper with the rawToken
      const tampered: TimestampToken = {
        ...token,
        rawToken: Buffer.from('tampered-data').toString('base64'),
      };
      const result = await mock.verifyTimestamp(tampered);
      expect(result).toBe(false);
    });

    it('requestTimestamp throws when shouldFail is set', async () => {
      mock.shouldFail = true;
      await expect(mock.requestTimestamp(VALID_MERKLE_ROOT)).rejects.toThrow(
        'Mock TSA failure'
      );
    });

    it('reset clears state', async () => {
      await mock.requestTimestamp(VALID_MERKLE_ROOT);
      mock.shouldFail = true;

      mock.reset();

      expect(mock.calls).toHaveLength(0);
      expect(mock.shouldFail).toBe(false);
    });

    it('different hashes produce different tokens', async () => {
      const token1 = await mock.requestTimestamp('a'.repeat(64));
      const token2 = await mock.requestTimestamp('b'.repeat(64));

      expect(token1.requestHash).not.toBe(token2.requestHash);
      expect(token1.responseHash).not.toBe(token2.responseHash);
      expect(token1.tokenId).not.toBe(token2.tokenId);
    });
  });
});
