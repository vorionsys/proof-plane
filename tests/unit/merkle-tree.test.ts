/**
 * Merkle Tree Tests
 *
 * Covers: empty trees, single/multi leaf, odd/even counts,
 * proof-of-inclusion, proof failure modes, large trees, determinism.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { MerkleTree, type MerkleProof } from '../../src/events/merkle-tree.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const ZERO_HASH = '0'.repeat(64);

/** SHA-256 hex of a string — mirrors the internal leaf hashing. */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** SHA-256 hex of the concatenation of two hex strings (internal node). */
function hashPair(left: string, right: string): string {
  return sha256(left + right);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('MerkleTree', () => {
  // ── Empty tree ───────────────────────────────────────────────────────────

  describe('empty tree', () => {
    it('should return zero hash as root', () => {
      const tree = new MerkleTree([]);
      expect(tree.getRoot()).toBe(ZERO_HASH);
    });

    it('should report leaf count of 0', () => {
      const tree = new MerkleTree([]);
      expect(tree.getLeafCount()).toBe(0);
    });

    it('should throw when requesting a proof', () => {
      const tree = new MerkleTree([]);
      expect(() => tree.getProof(0)).toThrow(RangeError);
    });
  });

  // ── Single leaf ──────────────────────────────────────────────────────────

  describe('single leaf tree', () => {
    it('should have root equal to the leaf hash', () => {
      const tree = new MerkleTree(['hello']);
      expect(tree.getRoot()).toBe(sha256('hello'));
    });

    it('should produce a valid proof with no siblings', () => {
      const tree = new MerkleTree(['hello']);
      const proof = tree.getProof(0);

      expect(proof.leaf).toBe(sha256('hello'));
      expect(proof.leafIndex).toBe(0);
      expect(proof.siblings).toHaveLength(0);
      expect(proof.root).toBe(sha256('hello'));
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });
  });

  // ── Two leaf tree ────────────────────────────────────────────────────────

  describe('two leaf tree', () => {
    it('should have root = hash(hash(a) + hash(b))', () => {
      const tree = new MerkleTree(['a', 'b']);
      const expected = hashPair(sha256('a'), sha256('b'));
      expect(tree.getRoot()).toBe(expected);
    });

    it('should produce valid proofs for both leaves', () => {
      const tree = new MerkleTree(['a', 'b']);
      const root = tree.getRoot();

      for (let i = 0; i < 2; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });

    it('proof for leaf 0 should have leaf 1 as right sibling', () => {
      const tree = new MerkleTree(['a', 'b']);
      const proof = tree.getProof(0);

      expect(proof.siblings).toHaveLength(1);
      expect(proof.siblings[0].hash).toBe(sha256('b'));
      expect(proof.siblings[0].position).toBe('right');
    });

    it('proof for leaf 1 should have leaf 0 as left sibling', () => {
      const tree = new MerkleTree(['a', 'b']);
      const proof = tree.getProof(1);

      expect(proof.siblings).toHaveLength(1);
      expect(proof.siblings[0].hash).toBe(sha256('a'));
      expect(proof.siblings[0].position).toBe('left');
    });
  });

  // ── Odd number of leaves ─────────────────────────────────────────────────

  describe('odd number of leaves', () => {
    it('should handle 3 leaves (last duplicated)', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      const root = tree.getRoot();

      // Level 0: [H(a), H(b), H(c)]
      // Level 1: [hash(H(a)+H(b)), hash(H(c)+H(c))]  <-- c duplicated
      // Level 2: [hash(L1[0]+L1[1])]
      const hA = sha256('a');
      const hB = sha256('b');
      const hC = sha256('c');
      const l1_0 = hashPair(hA, hB);
      const l1_1 = hashPair(hC, hC);
      const expectedRoot = hashPair(l1_0, l1_1);

      expect(root).toBe(expectedRoot);

      // All proofs should verify
      for (let i = 0; i < 3; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });

    it('should handle 5 leaves', () => {
      const leaves = ['a', 'b', 'c', 'd', 'e'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      expect(root).toHaveLength(64);

      for (let i = 0; i < 5; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });
  });

  // ── Even number of leaves ────────────────────────────────────────────────

  describe('even number of leaves', () => {
    it('should handle 4 leaves', () => {
      const leaves = ['a', 'b', 'c', 'd'];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      // Manual computation
      const hA = sha256('a');
      const hB = sha256('b');
      const hC = sha256('c');
      const hD = sha256('d');
      const l1_0 = hashPair(hA, hB);
      const l1_1 = hashPair(hC, hD);
      const expectedRoot = hashPair(l1_0, l1_1);

      expect(root).toBe(expectedRoot);

      for (let i = 0; i < 4; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });

    it('should handle 8 leaves', () => {
      const leaves = Array.from({ length: 8 }, (_, i) => `leaf-${i}`);
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      expect(root).toHaveLength(64);

      for (let i = 0; i < 8; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });
  });

  // ── Proof-of-inclusion: every leaf ────────────────────────────────────────

  describe('proof-of-inclusion verifies for every leaf', () => {
    const sizes = [1, 2, 3, 4, 5, 7, 8, 10, 16];

    for (const size of sizes) {
      it(`tree of ${size} leaves — all proofs verify`, () => {
        const leaves = Array.from({ length: size }, (_, i) => `item-${i}`);
        const tree = new MerkleTree(leaves);
        const root = tree.getRoot();

        for (let i = 0; i < size; i++) {
          const proof = tree.getProof(i);
          expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
        }
      });
    }
  });

  // ── Proof failure: wrong leaf data ────────────────────────────────────────

  describe('proof fails with wrong leaf data', () => {
    it('should not verify when leaf hash is wrong', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);

      // Use the hash of a completely different piece of data
      const wrongLeaf = sha256('WRONG');
      expect(MerkleTree.verify(wrongLeaf, proof, tree.getRoot())).toBe(false);
    });

    it('should not verify when siblings are tampered', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(1);

      // Tamper with the first sibling hash
      const tampered: MerkleProof = {
        ...proof,
        siblings: [
          { hash: sha256('TAMPERED'), position: proof.siblings[0].position },
          ...proof.siblings.slice(1),
        ],
      };

      expect(MerkleTree.verify(proof.leaf, tampered, tree.getRoot())).toBe(false);
    });
  });

  // ── Proof failure: wrong root ─────────────────────────────────────────────

  describe('proof fails with wrong root', () => {
    it('should not verify when root is incorrect', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(2);

      const wrongRoot = sha256('not-the-root');
      expect(MerkleTree.verify(proof.leaf, proof, wrongRoot)).toBe(false);
    });

    it('should not verify against a different tree root', () => {
      const tree1 = new MerkleTree(['a', 'b', 'c', 'd']);
      const tree2 = new MerkleTree(['w', 'x', 'y', 'z']);

      const proof = tree1.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, tree2.getRoot())).toBe(false);
    });
  });

  // ── Large tree ────────────────────────────────────────────────────────────

  describe('large tree (100 leaves)', () => {
    it('all 100 proofs verify', () => {
      const leaves = Array.from({ length: 100 }, (_, i) => `data-${i}`);
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      expect(root).toHaveLength(64);
      expect(tree.getLeafCount()).toBe(100);

      for (let i = 0; i < 100; i++) {
        const proof = tree.getProof(i);
        expect(proof.leafIndex).toBe(i);
        expect(proof.root).toBe(root);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });
  });

  // ── Determinism ───────────────────────────────────────────────────────────

  describe('deterministic', () => {
    it('same inputs produce the same root', () => {
      const leaves = ['alpha', 'beta', 'gamma', 'delta'];
      const tree1 = new MerkleTree(leaves);
      const tree2 = new MerkleTree(leaves);

      expect(tree1.getRoot()).toBe(tree2.getRoot());
    });

    it('same inputs produce identical proofs', () => {
      const leaves = ['alpha', 'beta', 'gamma', 'delta'];
      const tree1 = new MerkleTree(leaves);
      const tree2 = new MerkleTree(leaves);

      for (let i = 0; i < leaves.length; i++) {
        const p1 = tree1.getProof(i);
        const p2 = tree2.getProof(i);
        expect(p1).toEqual(p2);
      }
    });

    it('different inputs produce different roots', () => {
      const tree1 = new MerkleTree(['a', 'b']);
      const tree2 = new MerkleTree(['c', 'd']);
      expect(tree1.getRoot()).not.toBe(tree2.getRoot());
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('should throw RangeError for negative index', () => {
      const tree = new MerkleTree(['a', 'b']);
      expect(() => tree.getProof(-1)).toThrow(RangeError);
    });

    it('should throw RangeError for out-of-bounds index', () => {
      const tree = new MerkleTree(['a', 'b']);
      expect(() => tree.getProof(2)).toThrow(RangeError);
    });

    it('should accept Buffer leaves', () => {
      const tree = new MerkleTree([Buffer.from('hello'), Buffer.from('world')]);
      expect(tree.getRoot()).toHaveLength(64);

      const proof = tree.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });

    it('hashLeaf matches manual SHA-256', () => {
      const data = 'test-data';
      expect(MerkleTree.hashLeaf(data)).toBe(sha256(data));
    });
  });
});
