/**
 * Integrity Check Tests
 *
 * Tests for the proof-plane runtime self-integrity verification module.
 * Covers environment checks, manifest-based file hashing, and report
 * generation including self-referential report hashing.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  ProofPlaneIntegrityCheck,
  type IntegrityManifest,
  type IntegrityReport,
} from '../src/events/integrity-check.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function computeSHA256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Create a temporary dist/ directory with fake compiled files for testing.
 */
async function createTempDist(
  files: Record<string, string>,
): Promise<{ distDir: string; cleanup: () => Promise<void> }> {
  const base = join(tmpdir(), `proof-plane-integrity-test-${Date.now()}`);
  const distDir = join(base, 'dist');

  // Create all subdirectories and files
  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = join(distDir, relativePath);
    const dir = fullPath.substring(0, fullPath.lastIndexOf('/') >= 0 ? fullPath.lastIndexOf('/') : fullPath.lastIndexOf('\\'));
    await mkdir(dir, { recursive: true });
    await writeFile(fullPath, content, 'utf-8');
  }

  return {
    distDir,
    cleanup: async () => {
      await rm(base, { recursive: true, force: true });
    },
  };
}

/**
 * Build a manifest from file contents.
 */
function buildManifest(files: Record<string, string>): IntegrityManifest {
  const manifestFiles: Record<string, string> = {};
  for (const [path, content] of Object.entries(files)) {
    manifestFiles[path] = computeSHA256(content);
  }
  return {
    version: '0.1.3-test',
    buildTime: new Date().toISOString(),
    commitSha: 'abc123',
    nodeVersion: process.version,
    typescriptVersion: '5.7.2',
    files: manifestFiles,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('ProofPlaneIntegrityCheck', () => {
  describe('checkRuntimeEnvironment', () => {
    it('passes in normal Node.js environment', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const results = await checker.checkRuntimeEnvironment();

      // Node.js version check
      const nodeCheck = results.find((r) => r.check === 'node_version');
      expect(nodeCheck).toBeDefined();
      expect(nodeCheck!.passed).toBe(true);
      expect(nodeCheck!.actual).toBe(process.version);

      // WebCrypto availability
      const cryptoCheck = results.find((r) => r.check === 'webcrypto_available');
      expect(cryptoCheck).toBeDefined();
      expect(cryptoCheck!.passed).toBe(true);

      // SHA-256
      const sha256Check = results.find((r) => r.check === 'sha256_available');
      expect(sha256Check).toBeDefined();
      expect(sha256Check!.passed).toBe(true);

      // SHA3-256
      const sha3Check = results.find((r) => r.check === 'sha3_256_available');
      expect(sha3Check).toBeDefined();
      expect(sha3Check!.passed).toBe(true);

      // Ed25519
      const ed25519Check = results.find((r) => r.check === 'ed25519_available');
      expect(ed25519Check).toBeDefined();
      expect(ed25519Check!.passed).toBe(true);

      // All should pass
      expect(results.every((r) => r.passed)).toBe(true);
    });

    it('detects missing crypto.subtle support', async () => {
      // Save original
      const originalSubtle = globalThis.crypto?.subtle;

      // Mock crypto.subtle as undefined
      try {
        Object.defineProperty(globalThis.crypto, 'subtle', {
          value: undefined,
          writable: true,
          configurable: true,
        });

        const checker = new ProofPlaneIntegrityCheck();
        const results = await checker.checkRuntimeEnvironment();

        const cryptoCheck = results.find((r) => r.check === 'webcrypto_available');
        expect(cryptoCheck).toBeDefined();
        expect(cryptoCheck!.passed).toBe(false);
        expect(cryptoCheck!.actual).toBe('missing');

        // Ed25519 should also fail when subtle is missing
        const ed25519Check = results.find((r) => r.check === 'ed25519_available');
        expect(ed25519Check).toBeDefined();
        expect(ed25519Check!.passed).toBe(false);
      } finally {
        // Restore
        Object.defineProperty(globalThis.crypto, 'subtle', {
          value: originalSubtle,
          writable: true,
          configurable: true,
        });
      }
    });

    it('includes timestamps on all results', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const results = await checker.checkRuntimeEnvironment();

      for (const result of results) {
        expect(result.timestamp).toBeDefined();
        // Should be a valid ISO 8601 timestamp
        expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp);
      }
    });
  });

  describe('checkPackageIntegrity', () => {
    it('skips checks when no manifest is loaded (dev mode)', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const results = await checker.checkPackageIntegrity();

      expect(results.length).toBe(1);
      expect(results[0].check).toBe('package_integrity');
      expect(results[0].passed).toBe(true);
      expect(results[0].actual).toBe('manifest_not_found');
      expect(results[0].detail).toContain('No build manifest found');
    });

    it('passes with known-good manifest and matching files', async () => {
      const fileContents: Record<string, string> = {
        'events/hash-chain.js': 'const hashChain = "authentic code";',
        'events/event-signatures.js': 'const sigs = "authentic code";',
        'events/merkle-tree.js': 'const merkle = "authentic code";',
      };

      const { distDir, cleanup } = await createTempDist(fileContents);

      try {
        // Build manifest with hashes matching the file contents
        const manifestFiles: Record<string, string> = {};
        for (const [path, content] of Object.entries(fileContents)) {
          manifestFiles[path] = computeSHA256(content);
        }

        const manifest: IntegrityManifest = {
          version: '0.1.3',
          buildTime: new Date().toISOString(),
          commitSha: 'abc123',
          nodeVersion: process.version,
          typescriptVersion: '5.7.2',
          files: manifestFiles,
        };

        const checker = new ProofPlaneIntegrityCheck({ distDir, manifest });
        const results = await checker.checkPackageIntegrity();

        // All files that exist and are in manifest should pass
        const hashResults = results.filter((r) => r.check.startsWith('file_hash:'));
        for (const result of hashResults) {
          if (result.actual !== 'skipped') {
            expect(result.passed).toBe(true);
          }
        }
      } finally {
        await cleanup();
      }
    });

    it('detects modified file (tampered)', async () => {
      const originalContent = 'const hashChain = "authentic code";';
      const tamperedContent = 'const hashChain = "BACKDOORED code";';

      const { distDir, cleanup } = await createTempDist({
        'events/hash-chain.js': tamperedContent, // Write tampered version to disk
      });

      try {
        // Manifest has hash of the ORIGINAL content
        const manifest: IntegrityManifest = {
          version: '0.1.3',
          buildTime: nen: process.version,
          typescriptVersion: '5.7.2',
          files: {
            'events/hash-chain.js': computeSHA256(originalContent),
          },
        };

        const checker = new ProofPlaneIntegrityCheck({ distDir, manifest });
        const results = await checker.checkPackageIntegrity();

        const hashChainResult = results.find(
          (r) => r.check === 'file_hash:events/hash-chain.js',
        );
        expect(hashChainResult).toBeDefined();
        expect(hashChainResult!.passed).toBe(false);
        expect(hashChainResult!.expected).toBe(computeSHA256(originalContent));
        expect(hashChainResult!.actual).toBe(computeSHA256(tamperedContent));
        expect(hashChainResult!.detail).toContain('INTEGRITY VIOLATION');
      } finally {
        await cleanup();
      }
    });
  });

  describe('runAllChecks', () => {
    it('returns a complete report', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const report = await checker.runAllChecks();

      // Report structure
      expect(report.results).toBeDefined();
      expect(Array.isArray(report.results)).toBe(true);
      expect(report.results.length).toBeGreaterThan(0);
      expect(report.generatedAt).toBeDefined();
      expect(report.packageVersion).toBeDefined();
      expect(typeof report.allPassed).toBe('boolean');

      // Should include environment checks
      const checkNames = report.results.map((r) => r.check);
      expect(checkNames).toContain('node_version');
      expect(checkNames).toContain('webcrypto_available');
      expect(checkNames).toContain('sha256_available');
      expect(checkNames).toContain('sha3_256_available');
      expect(checkNames).toContain('ed25519_available');

      // Should include package integrity check (skipped in dev mode)
      const hasPackageCheck = checkNames.some(
        (n) => n === 'package_integrity' || n.startsWith('file_hash:'),
      );
      expect(hasPackageCheck).toBe(true);

      // Should include dependency check
      const hasDepCheck = checkNames.some((n) => n.startsWith('dep_version:'));
      expect(hasDepCheck).toBe(true);
    });

    it('includes a SHA-256 hash of the results (self-referential integrity)', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const report = await checker.runAllChecks();

      // Report hash should be present
      expect(report.reportHash).toBeDefined();
      expect(report.reportHash.length).toBe(64); // SHA-256 hex

      // Verify the hash matches the serialized results
      const expectedHash = computeSHA256(JSON.stringify(report.results));
      expect(report.reportHash).toBe(expectedHash);
    });

    it('allPassed is true when all checks pass in normal environment', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const report = await checker.runAllChecks();

      // In a normal Node.js 22 environment, all checks should pass
      expect(report.allPassed).toBe(true);
      for (const result of report.results) {
        expect(result.passed).toBe(true);
      }
    });

    it('allPassed is false when any check fails', async () => {
      // Create a checker with a manifest that has wrong hashes
      const manifest: IntegrityManifest = {
        version: '0.1.3',
        buildTime: new Date().toISOString(),
        commitSha: 'abc123',
        nodeVersion: process.version,
        typescriptVersion: '5.7.2',
        files: {
          // Hash that won't match any real file
          'events/hash-chain.js': 'deadbeef'.repeat(8),
        },
      };

      // Use a distDir that does not have matching files — the file will be "not found"
      const { distDir, cleanup } = await createTempDist({
        'events/hash-chain.js': 'different content',
      });

      try {
        const checker = new ProofPlaneIntegrityCheck({ distDir, manifest });
        const report = await checker.runAllChecks();

        // The file hash check should fail (content doesn't match manifest)
        expect(report.allPassed).toBe(false);

        const failedChecks = report.results.filter((r) => !r.passed);
        expect(failedChecks.length).toBeGreaterThan(0);
      } finally {
        await cleanup();
      }
    });

    it('report generatedAt is a valid ISO 8601 timestamp', async () => {
      const checker = new ProofPlaneIntegrityCheck();
      const report = await checker.runAllChecks();

      expect(new Date(report.generatedAt).toISOString()).toBe(report.generatedAt);
    });
  });

  describe('loadManifest', () => {
    it('loads manifest from disk when available', async () => {
      const manifest: IntegrityManifest = {
        version: '1.0.0',
        buildTime: '2026-04-04T00:00:00.000Z',
        commitSha: 'abc123',
        nodeVersion: 'v22.0.0',
        typescriptVersion: '5.7.2',
        files: {
          'events/hash-chain.js': 'a'.repeat(64),
        },
      };

      const { distDir, cleanup } = await createTempDist({
        'integrity-manifest.json': JSON.stringify(manifest),
      });

      try {
        const checker = new ProofPlaneIntegrityCheck({ distDir });
        const loaded = await checker.loadManifest();

        expect(loaded.version).toBe('1.0.0');
        expect(loaded.commitSha).toBe('abc123');
        expect(loaded.files['events/hash-chain.js']).toBe('a'.repeat(64));
      } finally {
        await cleanup();
      }
    });

    it('falls back to placeholder when manifest file is missing', async () => {
      const { distDir, cleanup } = await createTempDist({});

      try {
        const checker = new ProofPlaneIntegrityCheck({ distDir });
        const loaded = await checker.loadManifest();

        expect(loaded.version).toBe('0.0.0-dev');
        expect(loaded.commitSha).toBe('development');
      } finally {
        await cleanup();
      }
    });
  });
});
