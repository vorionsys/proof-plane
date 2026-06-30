/**
 * Merkle Tree - Binary Merkle tree for batch proof verification
 *
 * Provides efficient proof-of-inclusion for sets of data using a
 * standard binary Merkle tree with SHA-256 hashing, consistent
 * with the primary hash algorithm used in the proof-plane hash chain.
 */

import { createHash } from 'node:crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * A proof-of-inclusion for a single leaf in the Merkle tree.
 *
 * Walking the `siblings` array from index 0 upward, each entry tells you
 * whether to concatenate the sibling on the left or right before hashing,
 * until you arrive at the root.
 */
export interface MerkleProof {
  /** The SHA-256 hash of the original leaf data */
  leaf: string;
  /** The zero-based index of the leaf in the tree */
  leafIndex: number;
  /** Sibling hashes required to reconstruct the root */
  siblings: Array<{ hash: string; position: 'left' | 'right' }>;
  /** The Merkle root that the proof resolves to */
  root: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * The root hash returned for an empty tree (all-zero SHA-256 digest).
 */
const ZERO_HASH = '0'.repeat(64);

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Compute the SHA-256 hash of arbitrary string data (hex-encoded output).
 */
function hashData(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Compute the SHA-256 hash of two concatenated hex hashes.
 * This is the internal node hash function for the tree.
 */
function hashPair(left: string, right: string): string {
  return hashData(left + right);
}

// ─── MerkleTree ──────────────────────────────────────────────────────────────

/**
 * A standard binary Merkle tree built from an array of leaf data.
 *
 * Construction rules:
 * - Each leaf is SHA-256-hashed independently.
 * - If a level has an odd number of nodes the last node is duplicated.
 * - Internal nodes are the SHA-256 hash of `left_hex + right_hex`.
 * - An empty tree has a root of `ZERO_HASH` (64 hex zeros).
 *
 * @example
 * ```ts
 * const tree = new MerkleTree(['a', 'b', 'c', 'd']);
 * const root = tree.getRoot();
 * const proof = tree.getProof(2);
 * const valid = MerkleTree.verify(proof.leaf, proof, root); // true
 * ```
 */
export class MerkleTree {
  /** All levels of the tree, from leaves (index 0) to root (last). */
  private readonly levels: string[][];

  /**
   * Build a Merkle tree from an array of leaf data.
   *
   * @param leaves - Raw leaf data. Each element is hashed with SHA-256
   *                 to produce the leaf layer of the tree.
   */
  constructor(leaves: ReadonlyArray<Buffer | string>) {
    if (leaves.length === 0) {
      this.levels = [];
      return;
    }

    // Hash each leaf to produce level 0
    const leafHashes = leaves.map((leaf) => {
      const data = Buffer.isBuffer(leaf) ? leaf.toString('utf-8') : leaf;
      return hashData(data);
    });

    this.levels = MerkleTree.buildLevels(leafHashes);
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Return the Merkle root hash (hex string).
   * An empty tree returns `ZERO_HASH`.
   */
  getRoot(): string {
    if (this.levels.length === 0) {
      return ZERO_HASH;
    }
    return this.levels[this.levels.length - 1][0];
  }

  /**
   * Return the number of original leaves in the tree.
   */
  getLeafCount(): number {
    if (this.levels.length === 0) return 0;
    return this.levels[0].length;
  }

  /**
   * Generate a proof-of-inclusion for the leaf at `leafIndex`.
   *
   * @throws {RangeError} if `leafIndex` is out of bounds
   */
  getProof(leafIndex: number): MerkleProof {
    if (this.levels.length === 0) {
      throw new RangeError('Cannot generate proof for an empty tree');
    }
    const leafCount = this.levels[0].length;
    if (leafIndex < 0 || leafIndex >= leafCount) {
      throw new RangeError(
        `leafIndex ${leafIndex} is out of range [0, ${leafCount - 1}]`,
      );
    }

    const siblings: MerkleProof['siblings'] = [];
    let idx = leafIndex;

    // Walk from the leaf level up to (but not including) the root level
    for (let level = 0; level < this.levels.length - 1; level++) {
      const currentLevel = this.levels[level];

      // Determine the sibling index and its position relative to us
      const isLeft = idx % 2 === 0;
      const siblingIdx = isLeft ? idx + 1 : idx - 1;

      // When the level has an odd count the last node was duplicated during
      // construction, so the sibling of the last node is itself.
      const siblingHash =
        siblingIdx < currentLevel.length
          ? currentLevel[siblingIdx]
          : currentLevel[idx]; // duplicate of self

      siblings.push({
        hash: siblingHash,
        position: isLeft ? 'right' : 'left',
      });

      // Move to the parent index on the next level
      idx = Math.floor(idx / 2);
    }

    return {
      leaf: this.levels[0][leafIndex],
      leafIndex,
      siblings,
      root: this.getRoot(),
    };
  }

  // ── Static helpers ───────────────────────────────────────────────────────

  /**
   * Verify a proof-of-inclusion against a given root.
   *
   * @param leaf - The SHA-256 hash of the leaf data
   * @param proof - The `MerkleProof` to verify
   * @param root - The expected Merkle root hash
   * @returns `true` when the proof is valid
   */
  static verify(leaf: string, proof: MerkleProof, root: string): boolean {
    let current = leaf;

    for (const sibling of proof.siblings) {
      if (sibling.position === 'left') {
        current = hashPair(sibling.hash, current);
      } else {
        current = hashPair(current, sibling.hash);
      }
    }

    return current === root;
  }

  /**
   * Hash a raw data string with SHA-256 (convenience wrapper so consumers
   * can hash leaves identically to the tree without importing `crypto`).
   */
  static hashLeaf(data: string): string {
    return hashData(data);
  }

  // ── Internal construction ────────────────────────────────────────────────

  /**
   * Build every level of the tree from the leaf hashes up to the root.
   */
  private static buildLevels(leafHashes: string[]): string[][] {
    const levels: string[][] = [leafHashes];

    let current = leafHashes;

    while (current.length > 1) {
      const next: string[] = [];

      for (let i = 0; i < current.length; i += 2) {
        const left = current[i];
        // If odd number of nodes, duplicate the last one
        const right = i + 1 < current.length ? current[i + 1] : current[i];
        next.push(hashPair(left, right));
      }

      levels.push(next);
      current = next;
    }

    return levels;
  }
}
