/**
 * Proof Plane Logger - Implements the ProofPlaneLogger interface for A3I
 *
 * This bridges the A3I authorization engine with the Vorion proof plane,
 * automatically logging authorization decisions to the audit trail.
 */

import type { Intent, Decision } from '@vorionsys/contracts';
import { ProofPlane } from './proof-plane.js';

/**
 * Interface for proof plane logging (matches A3I's expected interface)
 */
export interface ProofPlaneLogger {
  logDecision(decision: Decision, intent: Intent): Promise<void>;
}

/**
 * Configuration for the proof plane logger
 */
export interface ProofPlaneLoggerConfig {
  /** The proof plane instance to use */
  proofPlane: ProofPlane;
  /** Whether to log intent received events */
  logIntentReceived?: boolean;
  /** Whether to log decision made events */
  logDecisionMade?: boolean;
}

/**
 * ProofPlaneLoggerImpl - Logs A3I events to the proof plane
 */
export class ProofPlaneLoggerImpl implements ProofPlaneLogger {
  private readonly proofPlane: ProofPlane;
  private readonly logIntentReceived: boolean;
  private readonly logDecisionMade: boolean;

  constructor(config: ProofPlaneLoggerConfig) {
    this.proofPlane = config.proofPlane;
    this.logIntentReceived = config.logIntentReceived ?? true;
    this.logDecisionMade = config.logDecisionMade ?? true;
  }

  /**
   * Log a decision (and optionally the intent)
   */
  async logDecision(decision: Decision, intent: Intent): Promise<void> {
    const correlationId = decision.correlationId;

    // Log intent received if enabled
    if (this.logIntentReceived) {
      await this.proofPlane.logIntentReceived(intent, correlationId);
    }

    // Log decision made if enabled
    if (this.logDecisionMade) {
      await this.proofPlane.logDecisionMade(decision, correlationId);
    }
  }
}

/**
 * Create a proof plane logger
 */
export function createProofPlaneLogger(config: ProofPlaneLoggerConfig): ProofPlaneLoggerImpl {
  return new ProofPlaneLoggerImpl(config);
}

/**
 * No-op logger for when proof plane is not connected
 */
export const noopProofPlaneLogger: ProofPlaneLogger = {
  async logDecision(_decision: Decision, _intent: Intent): Promise<void> {
    // No-op
  },
};
