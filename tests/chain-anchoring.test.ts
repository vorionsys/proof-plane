import { describe, it, expect, beforeEach } from 'vitest';
import {
  ChainAnchorService,
  MockAnchorService,
  type AnchorConfig,
  type AnchorRecord,
  type AnchorLogEntry,
} from '../src/events/chain-anchoring.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const VALID_MERKLE_ROOT = 'a'.repeat(64);
const ANOTHER_MERKLE_ROOT = 'b'.repeat(64);
const CHAIN_POSITION = 1000;

function createEnabledConfig(
  overrides?: Partial<AnchorConfig>,
): Partial<AnchorConfig> & Pick<AnchorConfig, 'strategy'> {
  const keys = ChainAnchorService.generateSigningKeys();
  return {
    strategy: 'merkle-root-log',
    enabled: true,
    signingPrivateKey: keys.privateKey,
    signingPublicKey: keys.publicKey,
    ...overrides,
  };
}

// ─── ChainAnchorService ───────────────────────────────────────────────────────

describe('ChainAnchorService', () => {
  describe('merkle-root-log strategy', () => {
    it('creates a valid anchor record', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      const record = await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);

      expect(record.anchorId).toBeTruthy();
      expect(record.merkleRoot).toBe(VALID_MERKLE_ROOT);
      expect(record.chainPosition).toBe(CHAIN_POSITION);
      expect(record.strategy).toBe('merkle-root-log');
      expect(record.externalReference).toMatch(/^[0-9a-f]{64}$/);
      expect(record.timestamp).toBeTruthy();
      expect(typeof record.verified).toBe('boolean');
    });

    it('anchor records include correct merkle root and chain position', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      const r1 = await service.anchor(VALID_MERKLE_ROOT, 500);
      const r2 = await service.anchor(ANOTHER_MERKLE_ROOT, 1000);

      expect(r1.merkleRoot).toBe(VALID_MERKLE_ROOT);
      expect(r1.chainPosition).toBe(500);
      expect(r2.merkleRoot).toBe(ANOTHER_MERKLE_ROOT);
      expect(r2.chainPosition).toBe(1000);
    });

    it('verify returns true for valid anchors', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      const record = await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);
      const valid = await service.verify(record);

      expect(valid).toBe(true);
    });

    it('verify returns detailed result for valid anchors', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      const record = await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);
      const result = await service.verifyDetailed(record);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.details).toContain('Anchor verified');
    });

    it('verify fails when merkle root is tampered', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      const record = await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);

      // Tamper with the merkle root in the record
      const tampered: AnchorRecord = { ...record, merkleRoot: ANOTHER_MERKLE_ROOT };
      const result = await service.verifyDetailed(tampered);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('Merkle root mismatch'))).toBe(true);
    });

    it('verify fails when external reference is missing', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      const record: AnchorRecord = {
        anchorId: 'test',
        merkleRoot: VALID_MERKLE_ROOT,
        chainPosition: CHAIN_POSITION,
        timestamp: new Date().toISOString(),
        strategy: 'merkle-root-log',
        externalReference: 'nonexistent-hash',
        verified: false,
      };

      const result = await service.verifyDetailed(record);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('Log entry not found'))).toBe(true);
    });

    it('verify fails without public key', async () => {
      const keys = ChainAnchorService.generateSigningKeys();
      const service = new ChainAnchorService({
        strategy: 'merkle-root-log',
        enabled: true,
        signingPrivateKey: keys.privateKey,
        // No public key
      });

      const record = await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);
      const result = await service.verifyDetailed(record);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('Missing signingPublicKey'))).toBe(true);
    });

    it('chains log entries with previousEntryHash', async () => {
      const config = createEnabledConfig();
      const entries: AnchorLogEntry[] = [];
      config.persistEntry = async (entry: AnchorLogEntry) => {
        entries.push(entry);
      };
      config.readEntries = async () => entries;

      const service = new ChainAnchorService(config);

      await service.anchor(VALID_MERKLE_ROOT, 500);
      await service.anchor(ANOTHER_MERKLE_ROOT, 1000);

      expect(entries).toHaveLength(2);
      expect(entries[0].previousEntryHash).toBeNull();
      expect(entries[1].previousEntryHash).toBe(entries[0].entryHash);
    });

    it('signs each log entry with Ed25519', async () => {
      const config = createEnabledConfig();
      const entries: AnchorLogEntry[] = [];
      config.persistEntry = async (entry: AnchorLogEntry) => {
        entries.push(entry);
      };
      config.readEntries = async () => entries;

      const service = new ChainAnchorService(config);
      await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);

      expect(entries[0].signature).toBeTruthy();
      // Base64 encoded Ed25519 signature should be non-empty
      expect(entries[0].signature.length).toBeGreaterThan(10);
    });
  });

  describe('getAnchors', () => {
    it('returns all anchors when no range specified', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 100);
      await service.anchor(ANOTHER_MERKLE_ROOT, 200);
      await service.anchor(VALID_MERKLE_ROOT, 300);

      const anchors = service.getAnchors();
      expect(anchors).toHaveLength(3);
    });

    it('filters by fromPosition', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 100);
      await service.anchor(ANOTHER_MERKLE_ROOT, 200);
      await service.anchor(VALID_MERKLE_ROOT, 300);

      const anchors = service.getAnchors(200);
      expect(anchors).toHaveLength(2);
      expect(anchors[0].chainPosition).toBe(200);
      expect(anchors[1].chainPosition).toBe(300);
    });

    it('filters by toPosition', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 100);
      await service.anchor(ANOTHER_MERKLE_ROOT, 200);
      await service.anchor(VALID_MERKLE_ROOT, 300);

      const anchors = service.getAnchors(undefined, 200);
      expect(anchors).toHaveLength(2);
      expect(anchors[0].chainPosition).toBe(100);
      expect(anchors[1].chainPosition).toBe(200);
    });

    it('filters by both fromPosition and toPosition', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 100);
      await service.anchor(ANOTHER_MERKLE_ROOT, 200);
      await service.anchor(VALID_MERKLE_ROOT, 300);
      await service.anchor(ANOTHER_MERKLE_ROOT, 400);

      const anchors = service.getAnchors(200, 300);
      expect(anchors).toHaveLength(2);
      expect(anchors[0].chainPosition).toBe(200);
      expect(anchors[1].chainPosition).toBe(300);
    });

    it('returns sorted by chain position', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 300);
      await service.anchor(ANOTHER_MERKLE_ROOT, 100);
      await service.anchor(VALID_MERKLE_ROOT, 200);

      const anchors = service.getAnchors();
      expect(anchors[0].chainPosition).toBe(100);
      expect(anchors[1].chainPosition).toBe(200);
      expect(anchors[2].chainPosition).toBe(300);
    });

    it('returns empty array when no anchors match range', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 100);
      const anchors = service.getAnchors(500, 1000);
      expect(anchors).toHaveLength(0);
    });
  });

  describe('shouldAnchor', () => {
    it('returns false when not enabled', () => {
      const service = new ChainAnchorService({
        strategy: 'merkle-root-log',
        enabled: false,
      });

      // Call many times
      for (let i = 0; i < 200; i++) {
        expect(service.shouldAnchor()).toBe(false);
      }
    });

    it('returns true after reaching batch interval', () => {
      const service = new ChainAnchorService({
        strategy: 'merkle-root-log',
        enabled: true,
        intervalBatches: 5,
      });

      for (let i = 0; i < 4; i++) {
        expect(service.shouldAnchor()).toBe(false);
      }
      // 5th call should trigger
      expect(service.shouldAnchor()).toBe(true);
    });

    it('resets after anchor is created', async () => {
      const service = new ChainAnchorService(
        createEnabledConfig({ intervalBatches: 3 }),
      );

      // Trigger threshold
      service.shouldAnchor();
      service.shouldAnchor();
      expect(service.shouldAnchor()).toBe(true);

      // Anchor resets counters
      await service.anchor(VALID_MERKLE_ROOT, 100);

      // Should not trigger immediately
      expect(service.shouldAnchor()).toBe(false);
      expect(service.shouldAnchor()).toBe(false);
      expect(service.shouldAnchor()).toBe(true);
    });
  });

  describe('error handling', () => {
    it('throws when not enabled', async () => {
      const service = new ChainAnchorService({
        strategy: 'merkle-root-log',
        enabled: false,
      });

      await expect(
        service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION),
      ).rejects.toThrow('not enabled');
    });

    it('throws when signing key is missing', async () => {
      const service = new ChainAnchorService({
        strategy: 'merkle-root-log',
        enabled: true,
        // No signingPrivateKey
      });

      await expect(
        service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION),
      ).rejects.toThrow('signingPrivateKey');
    });

    it('throws for blockchain strategy with clear message', async () => {
      const service = new ChainAnchorService({
        strategy: 'blockchain',
        enabled: true,
      });

      await expect(
        service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION),
      ).rejects.toThrow('CHAIN-ANCHORING.md');
    });

    it('throws for tsa strategy with clear message', async () => {
      const service = new ChainAnchorService({
        strategy: 'tsa',
        enabled: true,
      });

      await expect(
        service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION),
      ).rejects.toThrow('CHAIN-ANCHORING.md');
    });

    it('handles persistEntry failure gracefully', async () => {
      const config = createEnabledConfig();
      config.persistEntry = async () => {
        throw new Error('Disk full');
      };

      const service = new ChainAnchorService(config);

      await expect(
        service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION),
      ).rejects.toThrow('Disk full');
    });
  });

  describe('custom persistence', () => {
    it('calls persistEntry callback for each anchor', async () => {
      const persisted: AnchorLogEntry[] = [];
      const config = createEnabledConfig({
        persistEntry: async (entry) => {
          persisted.push(entry);
        },
        readEntries: async () => persisted,
      });

      const service = new ChainAnchorService(config);

      await service.anchor(VALID_MERKLE_ROOT, 100);
      await service.anchor(ANOTHER_MERKLE_ROOT, 200);

      expect(persisted).toHaveLength(2);
      expect(persisted[0].merkleRoot).toBe(VALID_MERKLE_ROOT);
      expect(persisted[1].merkleRoot).toBe(ANOTHER_MERKLE_ROOT);
    });

    it('verifies anchors using readEntries callback', async () => {
      const persisted: AnchorLogEntry[] = [];
      const config = createEnabledConfig({
        persistEntry: async (entry) => {
          persisted.push(entry);
        },
        readEntries: async () => persisted,
      });

      const service = new ChainAnchorService(config);
      const record = await service.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);

      const valid = await service.verify(record);
      expect(valid).toBe(true);
    });
  });

  describe('key generation', () => {
    it('generates valid Ed25519 key pair', () => {
      const keys = ChainAnchorService.generateSigningKeys();

      expect(keys.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keys.privateKey).toContain('BEGIN PRIVATE KEY');
    });

    it('generates unique key pairs', () => {
      const keys1 = ChainAnchorService.generateSigningKeys();
      const keys2 = ChainAnchorService.generateSigningKeys();

      expect(keys1.publicKey).not.toBe(keys2.publicKey);
      expect(keys1.privateKey).not.toBe(keys2.privateKey);
    });
  });

  describe('getAnchorCount', () => {
    it('returns zero initially', () => {
      const service = new ChainAnchorService(createEnabledConfig());
      expect(service.getAnchorCount()).toBe(0);
    });

    it('increments with each anchor', async () => {
      const service = new ChainAnchorService(createEnabledConfig());

      await service.anchor(VALID_MERKLE_ROOT, 100);
      expect(service.getAnchorCount()).toBe(1);

      await service.anchor(ANOTHER_MERKLE_ROOT, 200);
      expect(service.getAnchorCount()).toBe(2);
    });
  });
});

// ─── MockAnchorService ────────────────────────────────────────────────────────

describe('MockAnchorService', () => {
  let mock: MockAnchorService;

  beforeEach(() => {
    mock = new MockAnchorService();
  });

  it('creates anchor records', async () => {
    const record = await mock.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);

    expect(record.anchorId).toBeTruthy();
    expect(record.merkleRoot).toBe(VALID_MERKLE_ROOT);
    expect(record.chainPosition).toBe(CHAIN_POSITION);
    expect(record.verified).toBe(true);
  });

  it('verify returns true by default', async () => {
    const record = await mock.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);
    const valid = await mock.verify(record);
    expect(valid).toBe(true);
  });

  it('verify returns false when configured', async () => {
    mock.verifyReturnsFalse = true;
    const record = await mock.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);
    const valid = await mock.verify(record);
    expect(valid).toBe(false);
  });

  it('throws when shouldFail is set', async () => {
    mock.shouldFail = true;
    await expect(mock.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION)).rejects.toThrow(
      'Mock anchor failure',
    );
  });

  it('throws with custom failure message', async () => {
    mock.shouldFail = true;
    mock.failureMessage = 'Network timeout';
    await expect(mock.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION)).rejects.toThrow(
      'Network timeout',
    );
  });

  it('getAnchors returns stored records', async () => {
    await mock.anchor(VALID_MERKLE_ROOT, 100);
    await mock.anchor(ANOTHER_MERKLE_ROOT, 200);

    const anchors = mock.getAnchors();
    expect(anchors).toHaveLength(2);
  });

  it('getAnchors filters by position range', async () => {
    await mock.anchor(VALID_MERKLE_ROOT, 100);
    await mock.anchor(ANOTHER_MERKLE_ROOT, 200);
    await mock.anchor(VALID_MERKLE_ROOT, 300);

    const anchors = mock.getAnchors(200, 300);
    expect(anchors).toHaveLength(2);
  });

  it('tracks call counts', async () => {
    expect(mock.getAnchorCallCount()).toBe(0);
    expect(mock.getVerifyCallCount()).toBe(0);

    const record = await mock.anchor(VALID_MERKLE_ROOT, CHAIN_POSITION);
    expect(mock.getAnchorCallCount()).toBe(1);

    await mock.verify(record);
    expect(mock.getVerifyCallCount()).toBe(1);
  });

  it('reset clears all state', async () => {
    await mock.anchor(VALID_MERKLE_ROOT, 100);
    mock.shouldFail = true;
    mock.verifyReturnsFalse = true;

    mock.reset();

    expect(mock.getAnchorCallCount()).toBe(0);
    expect(mock.getVerifyCallCount()).toBe(0);
    expect(mock.getAnchors()).toHaveLength(0);
    // After reset, should not fail
    const record = await mock.anchor(VALID_MERKLE_ROOT, 100);
    const valid = await mock.verify(record);
    expect(valid).toBe(true);
  });
});
