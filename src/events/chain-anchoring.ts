/**
 * Third-Party Chain Anchoring for Proof Chain
 *
 * Publishes Merkle root hashes to external stores so that proof chain
 * state at a point in time can be verified by any third party without
 * trusting Vorion's infrastructure. This closes Gap 3 from the
 * Evidence Admissibility spec (SPEC-EVIDENCE-ADMISSIBILITY.md).
 *
 * Without external anchoring, a sophisticated attacker could replace
 * the ENTIRE proof chain with a fabricated one. Anchoring proves the
 * chain state existed at the recorded time to anyone who can read the
 * anchor store.
 *
 * Strategies:
 * - 'merkle-root-log': Append-only signed log file (ships now, usable immediately)
 * - 'blockchain': Ethereum L1/L2 anchoring (stub — requires ethers.js + wallet config)
 * - 'tsa': RFC 3161 Timestamp Authority (stub — see Gap 2 / rfc3161-client.ts)
 *
 * @packageDocumentation
 */

import { createHash, sign, verify, generateKeyPairSync } from 'node:crypto';
import { v4 as uuidv4 } from 'uuid';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Anchoring strategy.
 *
 * - `merkle-root-log`: Append Merkle roots + timestamps to a signed append-only
 *    log. Ed25519 signature on each entry. Minimum viable anchor — proves the
 *    Merkle root existed at the recorded time if the log is stored separately
 *    from the proof chain.
 * - `blockchain`: Ethereum L1/L2 transaction with Merkle root as data.
 *    Not yet implemented.
 * - `tsa`: RFC 3161 Timestamp Authority token binding.
 *    Not yet implemented.
 */
export type AnchorStrategy = 'merkle-root-log' | 'blockchain' | 'tsa';

/**
 * Configuration for the chain anchoring service.
 */
export interface AnchorConfig {
  /** Which anchoring strategy to use */
  strategy: AnchorStrategy;

  /**
   * Anchor every N batches (event flushes).
   * Ignored if intervalMs is also set — whichever triggers first wins.
   * @default 100
   */
  intervalBatches: number;

  /**
   * Anchor every N milliseconds.
   * @default 86_400_000 (24 hours)
   */
  intervalMs: number;

  /** Whether anchoring is enabled. @default false */
  enabled: boolean;

  // ── merkle-root-log strategy options ──

  /**
   * Ed25519 private key in PEM format for signing log entries.
   * Required for `merkle-root-log` strategy.
   */
  signingPrivateKey?: string;

  /**
   * Ed25519 public key in PEM format for verifying log entries.
   * Required for verification with `merkle-root-log` strategy.
   */
  signingPublicKey?: string;

  /**
   * Callback invoked to persist a log entry. The service does not prescribe
   * the storage backend — callers provide their own append function.
   * If not set, entries accumulate in memory (useful for testing).
   */
  persistEntry?: (entry: AnchorLogEntry) => Promise<void>;

  /**
   * Callback invoked to read all persisted log entries (for verification).
   * If not set, the in-memory store is used.
   */
  readEntries?: () => Promise<AnchorLogEntry[]>;

  // ── blockchain strategy options (future) ──

  /** Ethereum RPC endpoint */
  ethereumRpcUrl?: string;

  /** Ethereum wallet private key */
  ethereumPrivateKey?: string;

  /** Target chain: 'mainnet' | 'base' | 'arbitrum' | 'sepolia' */
  ethereumChain?: string;

  // ── tsa strategy options (future) ──

  /** RFC 3161 TSA endpoint URL */
  tsaEndpoint?: string;
}

/**
 * A single entry in the anchor log (merkle-root-log strategy).
 */
export interface AnchorLogEntry {
  /** The Merkle root being anchored */
  merkleRoot: string;

  /** Chain position (ordinal — how many events existed when this anchor was created) */
  chainPosition: number;

  /** ISO 8601 timestamp */
  timestamp: string;

  /** SHA-256 hash of (merkleRoot + chainPosition + timestamp + previousEntryHash) */
  entryHash: string;

  /** Hash of the previous log entry (null for the first entry) */
  previousEntryHash: string | null;

  /** Ed25519 signature of entryHash (base64) */
  signature: string;
}

/**
 * An anchor record — the public interface returned by the service.
 */
export interface AnchorRecord {
  /** Unique ID for this anchor */
  anchorId: string;

  /** The Merkle root that was anchored */
  merkleRoot: string;

  /** Chain position at anchor time */
  chainPosition: number;

  /** When the anchor was created */
  timestamp: string;

  /** Which strategy was used */
  strategy: AnchorStrategy;

  /**
   * External reference that proves existence.
   * - merkle-root-log: the entryHash of the signed log entry
   * - blockchain: transaction hash (future)
   * - tsa: base64 TSA token (future)
   */
  externalReference: string;

  /** Whether the anchor has been verified against the external store */
  verified: boolean;
}

/**
 * Result of anchor verification.
 */
export interface AnchorVerifyResult {
  /** Whether the anchor is valid */
  valid: boolean;

  /** Human-readable details */
  details: string;

  /** Errors encountered */
  errors: string[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Compute the SHA-256 hash of the canonical anchor entry data.
 */
function computeEntryHash(
  merkleRoot: string,
  chainPosition: number,
  timestamp: string,
  previousEntryHash: string | null,
): string {
  const canonical = JSON.stringify({
    merkleRoot,
    chainPosition,
    timestamp,
    previousEntryHash,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Sign data with Ed25519 (Node.js crypto).
 */
function ed25519Sign(data: string, privateKeyPem: string): string {
  const sig = sign(null, Buffer.from(data, 'utf-8'), privateKeyPem);
  return sig.toString('base64');
}

/**
 * Verify an Ed25519 signature.
 */
function ed25519Verify(data: string, signatureBase64: string, publicKeyPem: string): boolean {
  try {
    return verify(null, Buffer.from(data, 'utf-8'), publicKeyPem, Buffer.from(signatureBase64, 'base64'));
  } catch {
    return false;
  }
}

// ─── Default Config ───────────────────────────────────────────────────────────

const DEFAULT_INTERVAL_BATCHES = 100;
const DEFAULT_INTERVAL_MS = 86_400_000; // 24 hours

/**
 * Create a fully-populated config with defaults applied.
 */
function applyDefaults(partial: Partial<AnchorConfig> & Pick<AnchorConfig, 'strategy'>): AnchorConfig {
  return {
    strategy: partial.strategy,
    intervalBatches: partial.intervalBatches ?? DEFAULT_INTERVAL_BATCHES,
    intervalMs: partial.intervalMs ?? DEFAULT_INTERVAL_MS,
    enabled: partial.enabled ?? false,
    signingPrivateKey: partial.signingPrivateKey,
    signingPublicKey: partial.signingPublicKey,
    persistEntry: partial.persistEntry,
    readEntries: partial.readEntries,
    ethereumRpcUrl: partial.ethereumRpcUrl,
    ethereumPrivateKey: partial.ethereumPrivateKey,
    ethereumChain: partial.ethereumChain,
    tsaEndpoint: partial.tsaEndpoint,
  };
}

// ─── ChainAnchorService ───────────────────────────────────────────────────────

/**
 * Service that anchors proof chain Merkle roots to an external store,
 * proving chain state at a point in time to third parties.
 *
 * @example
 * ```ts
 * const keys = ChainAnchorService.generateSigningKeys();
 * const service = new ChainAnchorService({
 *   strategy: 'merkle-root-log',
 *   enabled: true,
 *   signingPrivateKey: keys.privateKey,
 *   signingPublicKey: keys.publicKey,
 * });
 *
 * const record = await service.anchor(merkleRoot, chainPosition);
 * const valid = await service.verify(record);
 * ```
 */
export class ChainAnchorService {
  private readonly config: AnchorConfig;

  /** In-memory log (used when no persistEntry/readEntries callbacks provided) */
  private readonly memoryLog: AnchorLogEntry[] = [];

  /** In-memory anchor record store */
  private readonly records: AnchorRecord[] = [];

  /** Batch counter for interval-based anchoring */
  private batchesSinceLastAnchor = 0;

  /** Timestamp of last anchor */
  private lastAnchorTime = 0;

  constructor(config: Partial<AnchorConfig> & Pick<AnchorConfig, 'strategy'>) {
    this.config = applyDefaults(config);
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Anchor a Merkle root + chain position to the configured external store.
   *
   * @param merkleRoot - The Merkle root hash to anchor (hex string)
   * @param chainPosition - How many events exist in the chain at this point
   * @returns The anchor record
   * @throws When the strategy is not implemented or misconfigured
   */
  async anchor(merkleRoot: string, chainPosition: number): Promise<AnchorRecord> {
    if (!this.config.enabled) {
      throw new Error('Chain anchoring is not enabled. Set config.enabled = true.');
    }

    switch (this.config.strategy) {
      case 'merkle-root-log':
        return this.anchorToLog(merkleRoot, chainPosition);
      case 'blockchain':
        throw new Error(
          "Strategy 'blockchain' requires additional configuration. " +
          'See docs/security/CHAIN-ANCHORING.md for setup instructions. ' +
          'Install ethers.js and provide ethereumRpcUrl + ethereumPrivateKey in config.',
        );
      case 'tsa':
        throw new Error(
          "Strategy 'tsa' requires additional configuration. " +
          'See docs/security/CHAIN-ANCHORING.md for setup instructions. ' +
          'Provide tsaEndpoint in config and see Gap 2 (RFC 3161) for the TSA client.',
        );
      default:
        throw new Error(`Unknown anchoring strategy: ${this.config.strategy}`);
    }
  }

  /**
   * Verify that an anchor record is still valid against the external store.
   *
   * For merkle-root-log: checks that the log entry exists, the signature is
   * valid, and the entry hash chain is intact.
   *
   * @returns true if the anchor is valid
   */
  async verify(record: AnchorRecord): Promise<boolean> {
    const result = await this.verifyDetailed(record);
    return result.valid;
  }

  /**
   * Verify with detailed result including error messages.
   */
  async verifyDetailed(record: AnchorRecord): Promise<AnchorVerifyResult> {
    if (record.strategy !== 'merkle-root-log') {
      return {
        valid: false,
        details: `Verification for strategy '${record.strategy}' is not yet implemented.`,
        errors: [`Unsupported strategy: ${record.strategy}`],
      };
    }

    return this.verifyLogEntry(record);
  }

  /**
   * Retrieve anchor records, optionally filtered by chain position range.
   *
   * @param fromPosition - Minimum chain position (inclusive)
   * @param toPosition - Maximum chain position (inclusive)
   */
  getAnchors(fromPosition?: number, toPosition?: number): AnchorRecord[] {
    let results = [...this.records];

    if (fromPosition !== undefined) {
      results = results.filter((r) => r.chainPosition >= fromPosition);
    }
    if (toPosition !== undefined) {
      results = results.filter((r) => r.chainPosition <= toPosition);
    }

    return results.sort((a, b) => a.chainPosition - b.chainPosition);
  }

  /**
   * Check whether it is time to anchor based on batch count or elapsed time.
   * Call this from the ProofCommitter flush cycle.
   *
   * @returns true if an anchor should be created now
   */
  shouldAnchor(): boolean {
    if (!this.config.enabled) return false;

    this.batchesSinceLastAnchor++;

    const batchThresholdMet = this.batchesSinceLastAnchor >= this.config.intervalBatches;
    const timeThresholdMet =
      this.lastAnchorTime > 0 && Date.now() - this.lastAnchorTime >= this.config.intervalMs;

    // First anchor: always anchor if batch threshold met
    if (this.lastAnchorTime === 0 && batchThresholdMet) return true;

    return batchThresholdMet || timeThresholdMet;
  }

  /**
   * Reset the batch counter after a successful anchor.
   * Called internally by anchor() but exposed for manual use.
   */
  resetCounters(): void {
    this.batchesSinceLastAnchor = 0;
    this.lastAnchorTime = Date.now();
  }

  /**
   * Get the number of anchor records stored.
   */
  getAnchorCount(): number {
    return this.records.length;
  }

  // ── Static helpers ────────────────────────────────────────────────────────

  /**
   * Generate an Ed25519 key pair for signing anchor log entries.
   * Convenience method for initial setup.
   *
   * @returns Object with `publicKey` and `privateKey` in PEM format
   */
  static generateSigningKeys(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    return {
      publicKey: publicKey.export({ type: 'spki', format: 'pem' }) as string,
      privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    };
  }

  // ── merkle-root-log strategy ──────────────────────────────────────────────

  private async anchorToLog(merkleRoot: string, chainPosition: number): Promise<AnchorRecord> {
    if (!this.config.signingPrivateKey) {
      throw new Error(
        "Strategy 'merkle-root-log' requires signingPrivateKey in config. " +
        'Generate keys with ChainAnchorService.generateSigningKeys().',
      );
    }

    const timestamp = new Date().toISOString();

    // Get the previous entry hash for chaining
    const previousEntryHash = await this.getLastEntryHash();

    // Compute the entry hash
    const entryHash = computeEntryHash(merkleRoot, chainPosition, timestamp, previousEntryHash);

    // Sign the entry hash
    const signature = ed25519Sign(entryHash, this.config.signingPrivateKey);

    const logEntry: AnchorLogEntry = {
      merkleRoot,
      chainPosition,
      timestamp,
      entryHash,
      previousEntryHash,
      signature,
    };

    // Persist
    if (this.config.persistEntry) {
      await this.config.persistEntry(logEntry);
    } else {
      this.memoryLog.push(logEntry);
    }

    // Create the anchor record
    const record: AnchorRecord = {
      anchorId: uuidv4(),
      merkleRoot,
      chainPosition,
      timestamp,
      strategy: 'merkle-root-log',
      externalReference: entryHash,
      verified: false,
    };

    this.records.push(record);
    this.resetCounters();

    return record;
  }

  private async getLastEntryHash(): Promise<string | null> {
    const entries = await this.getLogEntries();
    if (entries.length === 0) return null;
    return entries[entries.length - 1].entryHash;
  }

  private async getLogEntries(): Promise<AnchorLogEntry[]> {
    if (this.config.readEntries) {
      return this.config.readEntries();
    }
    return this.memoryLog;
  }

  private async verifyLogEntry(record: AnchorRecord): Promise<AnchorVerifyResult> {
    const errors: string[] = [];

    if (!this.config.signingPublicKey) {
      return {
        valid: false,
        details: 'Cannot verify: no signingPublicKey in config.',
        errors: ['Missing signingPublicKey'],
      };
    }

    // Find the log entry by its hash (externalReference)
    const entries = await this.getLogEntries();
    const entry = entries.find((e) => e.entryHash === record.externalReference);

    if (!entry) {
      return {
        valid: false,
        details: `Log entry not found for externalReference: ${record.externalReference}`,
        errors: ['Log entry not found'],
      };
    }

    // Verify the merkle root matches
    if (entry.merkleRoot !== record.merkleRoot) {
      errors.push(
        `Merkle root mismatch: record has ${record.merkleRoot}, log entry has ${entry.merkleRoot}`,
      );
    }

    // Verify the chain position matches
    if (entry.chainPosition !== record.chainPosition) {
      errors.push(
        `Chain position mismatch: record has ${record.chainPosition}, log entry has ${entry.chainPosition}`,
      );
    }

    // Verify the entry hash is correctly computed
    const expectedHash = computeEntryHash(
      entry.merkleRoot,
      entry.chainPosition,
      entry.timestamp,
      entry.previousEntryHash,
    );
    if (expectedHash !== entry.entryHash) {
      errors.push('Entry hash does not match recomputed hash — log entry may have been tampered with');
    }

    // Verify the Ed25519 signature
    const sigValid = ed25519Verify(entry.entryHash, entry.signature, this.config.signingPublicKey);
    if (!sigValid) {
      errors.push('Ed25519 signature verification failed');
    }

    // Verify the chain link (previousEntryHash)
    if (entry.previousEntryHash !== null) {
      const prevEntry = entries.find((e) => e.entryHash === entry.previousEntryHash);
      if (!prevEntry) {
        errors.push(`Previous entry not found: ${entry.previousEntryHash} — anchor log chain is broken`);
      }
    }

    const valid = errors.length === 0;

    return {
      valid,
      details: valid
        ? `Anchor verified: merkleRoot=${record.merkleRoot.slice(0, 12)}..., position=${record.chainPosition}`
        : `Anchor verification failed with ${errors.length} error(s)`,
      errors,
    };
  }
}

// ─── MockAnchorService ────────────────────────────────────────────────────────

/**
 * Mock anchor service for testing.
 *
 * Always succeeds, stores anchors in memory, and provides deterministic
 * behavior for test assertions.
 */
export class MockAnchorService {
  private readonly records: AnchorRecord[] = [];
  private anchorCallCount = 0;
  private verifyCallCount = 0;

  /** If true, the next anchor() call will throw */
  shouldFail = false;

  /** If true, verify() always returns false */
  verifyReturnsFalse = false;

  /** Custom error message for failures */
  failureMessage = 'Mock anchor failure';

  async anchor(merkleRoot: string, chainPosition: number): Promise<AnchorRecord> {
    this.anchorCallCount++;

    if (this.shouldFail) {
      throw new Error(this.failureMessage);
    }

    const record: AnchorRecord = {
      anchorId: uuidv4(),
      merkleRoot,
      chainPosition,
      timestamp: new Date().toISOString(),
      strategy: 'merkle-root-log',
      externalReference: `mock-ref-${this.anchorCallCount}`,
      verified: true,
    };

    this.records.push(record);
    return record;
  }

  async verify(_record: AnchorRecord): Promise<boolean> {
    this.verifyCallCount++;
    return !this.verifyReturnsFalse;
  }

  getAnchors(fromPosition?: number, toPosition?: number): AnchorRecord[] {
    let results = [...this.records];
    if (fromPosition !== undefined) {
      results = results.filter((r) => r.chainPosition >= fromPosition);
    }
    if (toPosition !== undefined) {
      results = results.filter((r) => r.chainPosition <= toPosition);
    }
    return results.sort((a, b) => a.chainPosition - b.chainPosition);
  }

  getAnchorCallCount(): number {
    return this.anchorCallCount;
  }

  getVerifyCallCount(): number {
    return this.verifyCallCount;
  }

  reset(): void {
    this.records.length = 0;
    this.anchorCallCount = 0;
    this.verifyCallCount = 0;
    this.shouldFail = false;
    this.verifyReturnsFalse = false;
  }
}
