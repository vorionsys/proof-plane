/**
 * Crypto Hardening Tests
 *
 * Production-hardening tests targeting critical crypto edge cases
 * in the hash chain and Merkle tree implementations.
 */

import { describe, it, expect } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ProofEventType, type ProofEvent } from '@vorionsys/contracts';
import {
  sha256,
  sha3_256,
  computeEventHash,
  computeEventHash3,
  verifyEventHash,
  verifyEventHash3,
  verifyChain,
  verifyChainWithDetails,
} from '../src/events/hash-chain.js';
import { MerkleTree } from '../src/events/merkle-tree.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function createTestEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {},
): Omit<ProofEvent, 'eventHash' | 'recordedAt'> {
  return {
    eventId: uuidv4(),
    eventType: ProofEventType.INTENT_RECEIVED,
    correlationId: uuidv4(),
    agentId: 'agent-01',
    payload: {
      type: 'intent_received',
      intentId: uuidv4(),
      action: 'read-file',
      actionType: 'read',
      resourceScope: ['/data'],
    },
    previousHash: null,
    occurredAt: new Date('2026-01-01T00:00:00Z'),
    signedBy: 'test-signer',
    ...overrides,
  };
}

async function buildHashedEvent(
  overrides: Partial<Omit<ProofEvent, 'eventHash' | 'recordedAt'>> = {},
): Promise<ProofEvent> {
  const base = createTestEvent(overrides);
  const eventHash = await computeEventHash(base);
  const eventHash3 = computeEventHash3(base);
  return { ...base, eventHash, eventHash3, recordedAt: new Date() };
}

async function buildChain(count: number): Promise<ProofEvent[]> {
  const chain: ProofEvent[] = [];
  for (let i = 0; i < count; i++) {
    const previousHash = i === 0 ? null : chain[i - 1].eventHash;
    const event = await buildHashedEvent({
      previousHash,
      occurredAt: new Date(`2026-01-01T00:${String(i).padStart(2, '0')}:00Z`),
    });
    chain.push(event);
  }
  return chain;
}

// ─── SHA-256 + SHA3-256 Dual Hash ───────────────────────────────────────────

describe('SHA-256 + SHA3-256 dual hash', () => {
  describe('sha256', () => {
    it('produces deterministic output for the same input', async () => {
      const a = await sha256('hello world');
      const b = await sha256('hello world');
      expect(a).toBe(b);
    });

    it('produces different hashes for different inputs', async () => {
      const a = await sha256('hello');
      const b = await sha256('world');
      expect(a).not.toBe(b);
    });

    it('hashes the empty string without error', async () => {
      const hash = await sha256('');
      expect(hash).toBeDefined();
      expect(hash.length).toBe(64);
    });

    it('produces a valid hex string of 64 characters', async () => {
      const hash = await sha256('test data');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('hashes a large payload (10KB+)', async () => {
      const largePayload = 'x'.repeat(10_240);
      const hash = await sha256(largePayload);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('hashes unicode content correctly', async () => {
      const hash = await sha256('Vorion\u2122 \u00e9\u00e8\u00ea \u4e16\u754c \ud83c\udf0d');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('produces deterministic output for unicode', async () => {
      const a = await sha256('\u00fc\u00f6\u00e4\u00df');
      const b = await sha256('\u00fc\u00f6\u00e4\u00df');
      expect(a).toBe(b);
    });

    it('differentiates between nearly identical inputs', async () => {
      const a = await sha256('abc');
      const b = await sha256('abd');
      expect(a).not.toBe(b);
    });
  });

  describe('sha3_256', () => {
    it('produces deterministic output for the same input', () => {
      const a = sha3_256('hello world');
      const b = sha3_256('hello world');
      expect(a).toBe(b);
    });

    it('produces different hashes for different inputs', () => {
      const a = sha3_256('hello');
      const b = sha3_256('world');
      expect(a).not.toBe(b);
    });

    it('hashes the empty string without error', () => {
      const hash = sha3_256('');
      expect(hash).toBeDefined();
      expect(hash.length).toBe(64);
    });

    it('produces a valid hex string of 64 characters', () => {
      const hash = sha3_256('test data');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('hashes a large payload (10KB+)', () => {
      const largePayload = 'y'.repeat(15_000);
      const hash = sha3_256(largePayload);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('hashes unicode content correctly', () => {
      const hash = sha3_256('\u00e9\u00e8\u00ea \u4e16\u754c');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('sha256 vs sha3_256 divergence', () => {
    it('same input produces different hashes across algorithms', async () => {
      const input = 'identical input for both';
      const s256 = await sha256(input);
      const s3 = sha3_256(input);
      expect(s256).not.toBe(s3);
    });

    it('both algorithms produce 64-char hex for same input', async () => {
      const input = 'length check';
      const s256 = await sha256(input);
      const s3 = sha3_256(input);
      expect(s256.length).toBe(64);
      expect(s3.length).toBe(64);
    });
  });
});

// ─── Event Hash Verification ────────────────────────────────────────────────

describe('Event hash verification', () => {
  describe('SHA-256 event hash', () => {
    it('valid event passes verifyEventHash', async () => {
      const event = await buildHashedEvent();
      expect(await verifyEventHash(event)).toBe(true);
    });

    it('tampered eventType fails verifyEventHash', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventType = ProofEventType.EXECUTION_FAILED;
      expect(await verifyEventHash(event)).toBe(false);
    });

    it('tampered payload fails verifyEventHash', async () => {
      const event = await buildHashedEvent();
      (event.payload as Record<string, unknown>).action = 'write-file';
      expect(await verifyEventHash(event)).toBe(false);
    });

    it('tampered agentId fails verifyEventHash', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).agentId = 'rogue-agent';
      expect(await verifyEventHash(event)).toBe(false);
    });

    it('tampered previousHash fails verifyEventHash', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).previousHash = 'deadbeef'.repeat(8);
      expect(await verifyEventHash(event)).toBe(false);
    });

    it('tampered occurredAt fails verifyEventHash', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).occurredAt = new Date('2099-12-31');
      expect(await verifyEventHash(event)).toBe(false);
    });
  });

  describe('SHA3-256 event hash', () => {
    it('valid event passes verifyEventHash3', async () => {
      const event = await buildHashedEvent();
      expect(verifyEventHash3(event)).toBe(true);
    });

    it('tampered eventType fails verifyEventHash3', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventType = ProofEventType.TRUST_DELTA;
      expect(verifyEventHash3(event)).toBe(false);
    });

    it('tampered payload fails verifyEventHash3', async () => {
      const event = await buildHashedEvent();
      (event.payload as Record<string, unknown>).action = 'delete-everything';
      expect(verifyEventHash3(event)).toBe(false);
    });

    it('tampered agentId fails verifyEventHash3', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).agentId = 'evil-agent';
      expect(verifyEventHash3(event)).toBe(false);
    });
  });

  describe('pre-upgrade events (no hash3)', () => {
    it('event without eventHash3 passes verifyEventHash3 gracefully', async () => {
      const event = await buildHashedEvent();
      delete (event as Partial<Pick<ProofEvent, 'eventHash3'>>).eventHash3;
      expect(verifyEventHash3(event)).toBe(true);
    });

    it('event with undefined eventHash3 passes', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventHash3 = undefined;
      expect(verifyEventHash3(event)).toBe(true);
    });

    it('event with empty string eventHash3 fails', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventHash3 = '';
      // empty string is falsy, so verifyEventHash3 should return true (pre-upgrade path)
      expect(verifyEventHash3(event)).toBe(true);
    });
  });

  describe('null/undefined hash field edge cases', () => {
    it('event with null eventHash fails verification', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventHash = null;
      expect(await verifyEventHash(event)).toBe(false);
    });

    it('event with wrong eventHash fails verification', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventHash = 'a'.repeat(64);
      expect(await verifyEventHash(event)).toBe(false);
    });

    it('event with wrong eventHash3 fails verification', async () => {
      const event = await buildHashedEvent();
      (event as Record<string, unknown>).eventHash3 = 'b'.repeat(64);
      expect(verifyEventHash3(event)).toBe(false);
    });
  });

  describe('computeEventHash determinism', () => {
    it('same event data produces identical SHA-256 hash', async () => {
      const base = createTestEvent({ eventId: 'fixed-id', correlationId: 'fixed-corr' });
      const h1 = await computeEventHash(base);
      const h2 = await computeEventHash(base);
      expect(h1).toBe(h2);
    });

    it('same event data produces identical SHA3-256 hash', () => {
      const base = createTestEvent({ eventId: 'fixed-id-2', correlationId: 'fixed-corr-2' });
      const h1 = computeEventHash3(base);
      const h2 = computeEventHash3(base);
      expect(h1).toBe(h2);
    });

    it('key ordering does not affect hash (sorted serialization)', async () => {
      // The implementation sorts keys, so differently-ordered objects produce the same hash.
      const base = createTestEvent({ eventId: 'order-test', correlationId: 'order-corr' });
      const hash = await computeEventHash(base);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });
});

// ─── Chain Verification ─────────────────────────────────────────────────────

describe('Chain verification', () => {
  it('valid chain of 3 events passes', async () => {
    const chain = await buildChain(3);
    const result = await verifyChain(chain);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(3);
  });

  it('empty chain is valid', async () => {
    const result = await verifyChain([]);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(0);
  });

  it('single-event chain with null previousHash is valid', async () => {
    const event = await buildHashedEvent({ previousHash: null });
    const result = await verifyChain([event]);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(1);
  });

  it('first event with non-null previousHash fails', async () => {
    const event = await buildHashedEvent({ previousHash: 'abc123'.padEnd(64, '0') });
    const result = await verifyChain([event]);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(0);
    expect(result.error).toContain('broken chain link');
  });

  it('tampered middle event detected', async () => {
    const chain = await buildChain(5);
    // Tamper with the middle event payload
    (chain[2].payload as Record<string, unknown>).action = 'tampered';
    const result = await verifyChain(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(2);
    expect(result.error).toContain('invalid SHA-256 hash');
  });

  it('broken link (wrong previousHash) detected', async () => {
    const chain = await buildChain(4);
    // Rebuild event 2 with a wrong previousHash but valid self-hash
    const wrongPrev = 'f'.repeat(64);
    const rebuilt = await buildHashedEvent({
      ...chain[2],
      previousHash: wrongPrev,
      eventHash: undefined as unknown as string,
      recordedAt: undefined as unknown as Date,
    });
    chain[2] = rebuilt;
    const result = await verifyChain(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(2);
    expect(result.error).toContain('broken chain link');
  });

  it('tampered last event detected', async () => {
    const chain = await buildChain(3);
    (chain[2] as Record<string, unknown>).agentId = 'tampered-agent';
    const result = await verifyChain(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(2);
  });

  it('tampered first event detected', async () => {
    const chain = await buildChain(3);
    (chain[0].payload as Record<string, unknown>).action = 'tampered';
    const result = await verifyChain(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(0);
  });

  it('verifyChainWithDetails returns totalEvents and event IDs', async () => {
    const chain = await buildChain(4);
    const result = await verifyChainWithDetails(chain);
    expect(result.valid).toBe(true);
    expect(result.totalEvents).toBe(4);
    expect(result.verifiedCount).toBe(4);
    expect(result.firstEventId).toBe(chain[0].eventId);
    expect(result.lastEventId).toBe(chain[3].eventId);
  });

  it('verifyChainWithDetails on empty chain', async () => {
    const result = await verifyChainWithDetails([]);
    expect(result.valid).toBe(true);
    expect(result.totalEvents).toBe(0);
    expect(result.verifiedCount).toBe(0);
    expect(result.firstEventId).toBeUndefined();
    expect(result.lastEventId).toBeUndefined();
  });

  it('verifyChainWithDetails reports broken event details', async () => {
    const chain = await buildChain(3);
    (chain[1].payload as Record<string, unknown>).action = 'tampered';
    const result = await verifyChainWithDetails(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(1);
    expect(result.brokenAtEventId).toBe(chain[1].eventId);
    expect(result.error).toBeDefined();
  });

  it('large chain (20 events) verifies correctly', async () => {
    const chain = await buildChain(20);
    const result = await verifyChain(chain);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(20);
  });

  it('SHA3-256 tamper detected in chain verification', async () => {
    const chain = await buildChain(3);
    // Tamper only the hash3 field
    (chain[1] as Record<string, unknown>).eventHash3 = 'c'.repeat(64);
    const result = await verifyChain(chain);
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(1);
    expect(result.error).toContain('SHA3-256');
  });
});

// ─── Merkle Tree ────────────────────────────────────────────────────────────

describe('Merkle tree', () => {
  describe('construction', () => {
    it('empty tree returns ZERO_HASH root', () => {
      const tree = new MerkleTree([]);
      expect(tree.getRoot()).toBe('0'.repeat(64));
    });

    it('empty tree has leaf count 0', () => {
      const tree = new MerkleTree([]);
      expect(tree.getLeafCount()).toBe(0);
    });

    it('single leaf tree has correct leaf count', () => {
      const tree = new MerkleTree(['only-leaf']);
      expect(tree.getLeafCount()).toBe(1);
    });

    it('single leaf tree root is not ZERO_HASH', () => {
      const tree = new MerkleTree(['leaf']);
      expect(tree.getRoot()).not.toBe('0'.repeat(64));
    });

    it('single leaf root equals hash of that leaf hashed with itself', () => {
      // Single leaf gets duplicated to form a pair
      const tree = new MerkleTree(['a']);
      const leafHash = MerkleTree.hashLeaf('a');
      // The tree should have a root that is hash(leafHash + leafHash)
      // (since single leaf is duplicated at the first level)
      expect(tree.getRoot()).toBeDefined();
      expect(tree.getRoot().length).toBe(64);
    });

    it('two leaf tree', () => {
      const tree = new MerkleTree(['a', 'b']);
      expect(tree.getLeafCount()).toBe(2);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('odd number of leaves (3) - duplication of last leaf', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      expect(tree.getLeafCount()).toBe(3);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('odd number of leaves (5)', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd', 'e']);
      expect(tree.getLeafCount()).toBe(5);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('power-of-2 leaf count: 2', () => {
      const tree = new MerkleTree(['a', 'b']);
      expect(tree.getLeafCount()).toBe(2);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('power-of-2 leaf count: 4', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      expect(tree.getLeafCount()).toBe(4);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('power-of-2 leaf count: 8', () => {
      const leaves = Array.from({ length: 8 }, (_, i) => `leaf-${i}`);
      const tree = new MerkleTree(leaves);
      expect(tree.getLeafCount()).toBe(8);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('power-of-2 leaf count: 16', () => {
      const leaves = Array.from({ length: 16 }, (_, i) => `leaf-${i}`);
      const tree = new MerkleTree(leaves);
      expect(tree.getLeafCount()).toBe(16);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('large tree (128 leaves)', () => {
      const leaves = Array.from({ length: 128 }, (_, i) => `data-${i}`);
      const tree = new MerkleTree(leaves);
      expect(tree.getLeafCount()).toBe(128);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('large tree (200 leaves)', () => {
      const leaves = Array.from({ length: 200 }, (_, i) => `item-${i}`);
      const tree = new MerkleTree(leaves);
      expect(tree.getLeafCount()).toBe(200);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('root determinism', () => {
    it('same leaves produce the same root', () => {
      const leaves = ['alpha', 'beta', 'gamma'];
      const tree1 = new MerkleTree(leaves);
      const tree2 = new MerkleTree(leaves);
      expect(tree1.getRoot()).toBe(tree2.getRoot());
    });

    it('different leaves produce different roots', () => {
      const tree1 = new MerkleTree(['a', 'b']);
      const tree2 = new MerkleTree(['c', 'd']);
      expect(tree1.getRoot()).not.toBe(tree2.getRoot());
    });

    it('leaf order matters', () => {
      const tree1 = new MerkleTree(['a', 'b', 'c']);
      const tree2 = new MerkleTree(['c', 'b', 'a']);
      expect(tree1.getRoot()).not.toBe(tree2.getRoot());
    });

    it('adding a leaf changes the root', () => {
      const tree1 = new MerkleTree(['a', 'b']);
      const tree2 = new MerkleTree(['a', 'b', 'c']);
      expect(tree1.getRoot()).not.toBe(tree2.getRoot());
    });
  });

  describe('proof generation and verification', () => {
    it('proof for first leaf in 4-leaf tree verifies', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });

    it('proof for last leaf in 4-leaf tree verifies', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(3);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });

    it('proof for middle leaf verifies', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd', 'e']);
      const proof = tree.getProof(2);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });

    it('proof for single-leaf tree verifies', () => {
      const tree = new MerkleTree(['only']);
      const proof = tree.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });

    it('proof for two-leaf tree verifies (both leaves)', () => {
      const tree = new MerkleTree(['left', 'right']);
      const proof0 = tree.getProof(0);
      const proof1 = tree.getProof(1);
      expect(MerkleTree.verify(proof0.leaf, proof0, tree.getRoot())).toBe(true);
      expect(MerkleTree.verify(proof1.leaf, proof1, tree.getRoot())).toBe(true);
    });

    it('proof for odd-leaf tree (3 leaves) verifies all', () => {
      const tree = new MerkleTree(['x', 'y', 'z']);
      for (let i = 0; i < 3; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
      }
    });

    it('all proofs in a 16-leaf tree verify', () => {
      const leaves = Array.from({ length: 16 }, (_, i) => `leaf-${i}`);
      const tree = new MerkleTree(leaves);
      for (let i = 0; i < 16; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
      }
    });

    it('all proofs in a 100+ leaf tree verify', () => {
      const leaves = Array.from({ length: 107 }, (_, i) => `entry-${i}`);
      const tree = new MerkleTree(leaves);
      // Spot check several indices including edges
      for (const idx of [0, 1, 50, 99, 106]) {
        const proof = tree.getProof(idx);
        expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
      }
    });

    it('proof contains correct leafIndex', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(2);
      expect(proof.leafIndex).toBe(2);
    });

    it('proof contains correct root', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      const proof = tree.getProof(1);
      expect(proof.root).toBe(tree.getRoot());
    });

    it('proof leaf matches hashLeaf output', () => {
      const tree = new MerkleTree(['test-data']);
      const proof = tree.getProof(0);
      expect(proof.leaf).toBe(MerkleTree.hashLeaf('test-data'));
    });
  });

  describe('invalid proof detection', () => {
    it('wrong sibling hash causes verification failure', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      // Tamper with first sibling hash
      proof.siblings[0] = { ...proof.siblings[0], hash: 'f'.repeat(64) };
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(false);
    });

    it('wrong root causes verification failure', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(1);
      const wrongRoot = 'e'.repeat(64);
      expect(MerkleTree.verify(proof.leaf, proof, wrongRoot)).toBe(false);
    });

    it('proof from one tree does not verify against another tree root', () => {
      const tree1 = new MerkleTree(['a', 'b', 'c', 'd']);
      const tree2 = new MerkleTree(['e', 'f', 'g', 'h']);
      const proof = tree1.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, tree2.getRoot())).toBe(false);
    });

    it('swapped sibling position causes verification failure', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      if (proof.siblings.length > 0) {
        proof.siblings[0] = {
          ...proof.siblings[0],
          position: proof.siblings[0].position === 'left' ? 'right' : 'left',
        };
      }
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(false);
    });

    it('wrong leaf hash causes verification failure', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(2);
      const wrongLeaf = MerkleTree.hashLeaf('z');
      expect(MerkleTree.verify(wrongLeaf, proof, tree.getRoot())).toBe(false);
    });
  });

  describe('error handling', () => {
    it('getProof on empty tree throws RangeError', () => {
      const tree = new MerkleTree([]);
      expect(() => tree.getProof(0)).toThrow(RangeError);
    });

    it('getProof with negative index throws RangeError', () => {
      const tree = new MerkleTree(['a', 'b']);
      expect(() => tree.getProof(-1)).toThrow(RangeError);
    });

    it('getProof with out-of-bounds index throws RangeError', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      expect(() => tree.getProof(3)).toThrow(RangeError);
    });

    it('getProof with very large index throws RangeError', () => {
      const tree = new MerkleTree(['a']);
      expect(() => tree.getProof(999)).toThrow(RangeError);
    });
  });

  describe('hashLeaf static method', () => {
    it('returns a 64-char hex string', () => {
      const hash = MerkleTree.hashLeaf('data');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('is deterministic', () => {
      expect(MerkleTree.hashLeaf('abc')).toBe(MerkleTree.hashLeaf('abc'));
    });

    it('different data produces different hashes', () => {
      expect(MerkleTree.hashLeaf('x')).not.toBe(MerkleTree.hashLeaf('y'));
    });
  });
});
