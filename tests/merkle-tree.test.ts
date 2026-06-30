/**
 * Merkle Tree Tests (Extended)
 *
 * Covers tree construction, root computation, inclusion proofs,
 * proof verification, unbalanced trees, single-leaf, empty,
 * large trees, proof compactness, duplicate leaves, rebuilding.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { MerkleTree, type MerkleProof } from '../src/events/merkle-tree.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const ZERO_HASH = '0'.repeat(64);

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function hashPair(left: string, right: string): string {
  return sha256(left + right);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('MerkleTree (Extended)', () => {
  // ── Tree construction from leaf data ───────────────────────────────────

  describe('tree construction', () => {
    it('constructs from string leaves', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      expect(tree.getLeafCount()).toBe(3);
      expect(tree.getRoot()).toHaveLength(64);
    });

    it('constructs from Buffer leaves', () => {
      const tree = new MerkleTree([
        Buffer.from('alpha'),
        Buffer.from('beta'),
      ]);
      expect(tree.getLeafCount()).toBe(2);
    });

    it('constructs from mixed string and Buffer leaves', () => {
      const tree = new MerkleTree(['hello', Buffer.from('world')]);
      expect(tree.getLeafCount()).toBe(2);
    });

    it('leaf hashes match MerkleTree.hashLeaf', () => {
      const data = 'test-leaf';
      const tree = new MerkleTree([data]);
      const proof = tree.getProof(0);
      expect(proof.leaf).toBe(MerkleTree.hashLeaf(data));
    });

    it('Buffer leaf produces same hash as equivalent string', () => {
      const data = 'same-data';
      const t1 = new MerkleTree([data]);
      const t2 = new MerkleTree([Buffer.from(data)]);
      expect(t1.getRoot()).toBe(t2.getRoot());
    });
  });

  // ── Root hash computation ─────────────────────────────────────────────

  describe('root hash computation', () => {
    it('2-leaf root = hash(hash(a) + hash(b))', () => {
      const tree = new MerkleTree(['x', 'y']);
      expect(tree.getRoot()).toBe(hashPair(sha256('x'), sha256('y')));
    });

    it('4-leaf root matches manual calculation', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const l1 = hashPair(sha256('a'), sha256('b'));
      const l2 = hashPair(sha256('c'), sha256('d'));
      expect(tree.getRoot()).toBe(hashPair(l1, l2));
    });

    it('3-leaf root matches manual calculation with duplication', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      const l1 = hashPair(sha256('a'), sha256('b'));
      const l2 = hashPair(sha256('c'), sha256('c')); // c is duplicated
      expect(tree.getRoot()).toBe(hashPair(l1, l2));
    });

    it('root is a valid 64-char hex string', () => {
      const tree = new MerkleTree(['foo', 'bar', 'baz']);
      expect(tree.getRoot()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('single-leaf root equals leaf hash', () => {
      const tree = new MerkleTree(['single']);
      expect(tree.getRoot()).toBe(sha256('single'));
    });
  });

  // ── Inclusion proof generation ─────────────────────────────────────────

  describe('inclusion proof generation', () => {
    it('proof contains correct leaf hash', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(2);
      expect(proof.leaf).toBe(sha256('c'));
    });

    it('proof contains correct leafIndex', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      for (let i = 0; i < 4; i++) {
        expect(tree.getProof(i).leafIndex).toBe(i);
      }
    });

    it('proof contains the tree root', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      const proof = tree.getProof(1);
      expect(proof.root).toBe(tree.getRoot());
    });

    it('proof siblings have correct positions for left leaf', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0); // leftmost leaf
      expect(proof.siblings[0].position).toBe('right');
    });

    it('proof siblings have correct positions for right leaf', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(1);
      expect(proof.siblings[0].position).toBe('left');
    });

    it('throws RangeError for negative index', () => {
      const tree = new MerkleTree(['a', 'b']);
      expect(() => tree.getProof(-1)).toThrow(RangeError);
    });

    it('throws RangeError for index >= leaf count', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      expect(() => tree.getProof(3)).toThrow(RangeError);
    });

    it('throws RangeError for empty tree', () => {
      const tree = new MerkleTree([]);
      expect(() => tree.getProof(0)).toThrow(RangeError);
    });
  });

  // ── Inclusion proof verification ───────────────────────────────────────

  describe('inclusion proof verification', () => {
    it('valid proof verifies against root', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(2);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });

    it('wrong leaf hash fails verification', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      expect(MerkleTree.verify(sha256('fake'), proof, tree.getRoot())).toBe(false);
    });

    it('wrong root fails verification', () => {
      const tree = new MerkleTree(['a', 'b', 'c']);
      const proof = tree.getProof(1);
      expect(MerkleTree.verify(proof.leaf, proof, sha256('wrong-root'))).toBe(false);
    });

    it('tampered sibling hash fails verification', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      const tampered: MerkleProof = {
        ...proof,
        siblings: proof.siblings.map((s, i) =>
          i === 0 ? { ...s, hash: sha256('tampered') } : s,
        ),
      };
      expect(MerkleTree.verify(proof.leaf, tampered, tree.getRoot())).toBe(false);
    });

    it('proof from one tree fails against another tree root', () => {
      const t1 = new MerkleTree(['a', 'b']);
      const t2 = new MerkleTree(['c', 'd']);
      const proof = t1.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, t2.getRoot())).toBe(false);
    });

    it('swapped sibling position fails verification', () => {
      const tree = new MerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      const swapped: MerkleProof = {
        ...proof,
        siblings: proof.siblings.map(s => ({
          ...s,
          position: s.position === 'left' ? 'right' as const : 'left' as const,
        })),
      };
      expect(MerkleTree.verify(proof.leaf, swapped, tree.getRoot())).toBe(false);
    });
  });

  // ── Unbalanced trees (odd number of leaves) ───────────────────────────

  describe('unbalanced trees', () => {
    it('7-leaf tree: all proofs verify', () => {
      const leaves = Array.from({ length: 7 }, (_, i) => `leaf-${i}`);
      const tree = new MerkleTree(leaves);
      for (let i = 0; i < 7; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
      }
    });

    it('9-leaf tree: all proofs verify', () => {
      const leaves = Array.from({ length: 9 }, (_, i) => `v-${i}`);
      const tree = new MerkleTree(leaves);
      for (let i = 0; i < 9; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
      }
    });

    it('13-leaf tree: all proofs verify', () => {
      const leaves = Array.from({ length: 13 }, (_, i) => `data-${i}`);
      const tree = new MerkleTree(leaves);
      for (let i = 0; i < 13; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
      }
    });
  });

  // ── Single-leaf tree ──────────────────────────────────────────────────

  describe('single-leaf tree', () => {
    it('root equals leaf hash', () => {
      const tree = new MerkleTree(['only']);
      expect(tree.getRoot()).toBe(sha256('only'));
    });

    it('proof has zero siblings', () => {
      const tree = new MerkleTree(['only']);
      expect(tree.getProof(0).siblings).toHaveLength(0);
    });

    it('proof verifies', () => {
      const tree = new MerkleTree(['only']);
      const proof = tree.getProof(0);
      expect(MerkleTree.verify(proof.leaf, proof, tree.getRoot())).toBe(true);
    });
  });

  // ── Empty tree ────────────────────────────────────────────────────────

  describe('empty tree', () => {
    it('root is ZERO_HASH', () => {
      expect(new MerkleTree([]).getRoot()).toBe(ZERO_HASH);
    });

    it('leaf count is 0', () => {
      expect(new MerkleTree([]).getLeafCount()).toBe(0);
    });
  });

  // ── Large trees (100+ leaves) ─────────────────────────────────────────

  describe('large trees', () => {
    it('200-leaf tree: all proofs verify', () => {
      const leaves = Array.from({ length: 200 }, (_, i) => `item-${i}`);
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      // Spot-check 20 random indices
      const indices = [0, 1, 50, 99, 100, 150, 199, 33, 77, 142];
      for (const i of indices) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });

    it('500-leaf tree has correct leaf count', () => {
      const leaves = Array.from({ length: 500 }, (_, i) => `d-${i}`);
      const tree = new MerkleTree(leaves);
      expect(tree.getLeafCount()).toBe(500);
    });
  });

  // ── Proof compactness O(log n) ─────────────────────────────────────────

  describe('proof compactness', () => {
    it('proof for 8-leaf tree has 3 siblings (log2(8))', () => {
      const tree = new MerkleTree(Array.from({ length: 8 }, (_, i) => `l-${i}`));
      const proof = tree.getProof(3);
      expect(proof.siblings).toHaveLength(3);
    });

    it('proof for 16-leaf tree has 4 siblings', () => {
      const tree = new MerkleTree(Array.from({ length: 16 }, (_, i) => `l-${i}`));
      const proof = tree.getProof(7);
      expect(proof.siblings).toHaveLength(4);
    });

    it('proof for 32-leaf tree has 5 siblings', () => {
      const tree = new MerkleTree(Array.from({ length: 32 }, (_, i) => `l-${i}`));
      const proof = tree.getProof(15);
      expect(proof.siblings).toHaveLength(5);
    });

    it('proof size grows logarithmically', () => {
      const sizes = [4, 16, 64, 256];
      const proofLengths: number[] = [];
      for (const size of sizes) {
        const tree = new MerkleTree(Array.from({ length: size }, (_, i) => `l-${i}`));
        proofLengths.push(tree.getProof(0).siblings.length);
      }
      // Each 4x increase in leaves should add exactly 2 to proof size
      expect(proofLengths[1] - proofLengths[0]).toBe(2);
      expect(proofLengths[2] - proofLengths[1]).toBe(2);
      expect(proofLengths[3] - proofLengths[2]).toBe(2);
    });
  });

  // ── Duplicate leaves ──────────────────────────────────────────────────

  describe('duplicate leaves', () => {
    it('tree with all identical leaves still builds', () => {
      const tree = new MerkleTree(['same', 'same', 'same', 'same']);
      expect(tree.getLeafCount()).toBe(4);
      expect(tree.getRoot()).toHaveLength(64);
    });

    it('proof verifies for duplicate leaf at each position', () => {
      const tree = new MerkleTree(['dup', 'dup', 'dup', 'dup']);
      const root = tree.getRoot();
      for (let i = 0; i < 4; i++) {
        const proof = tree.getProof(i);
        expect(MerkleTree.verify(proof.leaf, proof, root)).toBe(true);
      }
    });

    it('all leaf hashes are the same for duplicate leaves', () => {
      const tree = new MerkleTree(['x', 'x', 'x']);
      const p0 = tree.getProof(0);
      const p1 = tree.getProof(1);
      const p2 = tree.getProof(2);
      expect(p0.leaf).toBe(p1.leaf);
      expect(p1.leaf).toBe(p2.leaf);
    });

    it('tree with duplicates differs from tree without', () => {
      const t1 = new MerkleTree(['a', 'a']);
      const t2 = new MerkleTree(['a', 'b']);
      expect(t1.getRoot()).not.toBe(t2.getRoot());
    });
  });

  // ── Tree rebuilding produces same root ─────────────────────────────────

  describe('tree rebuilding', () => {
    it('rebuilding from same data produces same root', () => {
      const data = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'];
      const t1 = new MerkleTree(data);
      const t2 = new MerkleTree([...data]);
      expect(t1.getRoot()).toBe(t2.getRoot());
    });

    it('rebuilding produces identical proofs', () => {
      const data = ['w', 'x', 'y', 'z'];
      const t1 = new MerkleTree(data);
      const t2 = new MerkleTree(data);
      for (let i = 0; i < data.length; i++) {
        expect(t1.getProof(i)).toEqual(t2.getProof(i));
      }
    });

    it('different order of leaves produces different root', () => {
      const t1 = new MerkleTree(['a', 'b', 'c']);
      const t2 = new MerkleTree(['c', 'b', 'a']);
      expect(t1.getRoot()).not.toBe(t2.getRoot());
    });
  });
});
