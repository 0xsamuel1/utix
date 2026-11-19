import crypto from 'crypto';
import {
  WebhookSignature,
  WebhookMessage,
  WebhookVerificationConfig,
  ReplayProtectionRecord,
  WebhookSubscriber,
  WebhookDeliveryAttempt,
  ReplayWindowErrorCode,
  ReplayWindowOptions,
  ReplayWindowVerificationResult
} from './types';
import { err, ok, type Result } from '@/core/result/result';

/** Upper bound on a message's serialized `data`, before any hashing happens. */
export const MAX_WEBHOOK_DATA_LENGTH = 256 * 1024;
/** Upper bound on a nonce; replay records are keyed by it. */
export const MAX_WEBHOOK_NONCE_LENGTH = 128;
/** Maximum nonces stored in-memory to prevent resource exhaustion attacks. */
export const MAX_REPLAY_NONCES_CAPACITY = 50_000;

const SUPPORTED_ALGORITHMS = ['sha256', 'sha512'];

/**
 * Structural check for an untrusted message. Returns the reason it is
 * malformed, or null. Runs before the clock, replay and HMAC checks so a bad
 * payload is rejected deterministically instead of throwing or being hashed.
 */
function malformedReason(message: unknown): string | null {
  if (typeof message !== 'object' || message === null) return 'message must be an object';
  const { signature, data } = message as { signature?: unknown; data?: unknown };
  if (typeof signature !== 'object' || signature === null) return 'missing signature';
  const { algorithm, timestamp, nonce, signature: digest } = signature as Record<string, unknown>;
  if (typeof algorithm !== 'string' || !SUPPORTED_ALGORITHMS.includes(algorithm)) {
    return 'unsupported algorithm';
  }
  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) return 'invalid timestamp';
  if (typeof nonce !== 'string' || nonce.length === 0) return 'missing nonce';
  if (nonce.length > MAX_WEBHOOK_NONCE_LENGTH) return 'nonce too long';
  if (typeof digest !== 'string' || digest.length === 0) return 'missing signature digest';
  if (data === undefined) return 'missing data';
  try {
    const serialized = JSON.stringify(data);
    if (serialized !== undefined && serialized.length > MAX_WEBHOOK_DATA_LENGTH) return 'data too large';
  } catch {
    return 'data is not serializable';
  }
  return null;
}

export class WebhookVerifier {
  private defaultConfig: WebhookVerificationConfig = {
    replayWindowSeconds: 300,
    algorithmPreference: 'sha256',
    nonceDeduplication: true,
    maxClockSkew: 60,
  };

  private replayRecords: Map<string, ReplayProtectionRecord> = new Map();
  private nonceQueue: Array<{ nonce: string; timestamp: number }> = [];
  private subscribers: Map<string, WebhookSubscriber> = new Map();
  private deliveryAttempts: DeliveryAttempt[] = [];

  constructor(private config: Partial<WebhookVerificationConfig> = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  generateSignature(payload: string, secret: string, algorithm: 'sha256' | 'sha512' = 'sha256'): string {
    return crypto
      .createHmac(algorithm, secret)
      .update(payload)
      .digest('hex');
  }

  createSignedMessage(payload: unknown, secret: string): WebhookMessage {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex');
    const algorithm = this.config.algorithmPreference || 'sha256';

    const payloadString = JSON.stringify(payload);
    const signingString = `${timestamp}.${nonce}.${payloadString}`;
    const signature = this.generateSignature(signingString, secret, algorithm);

    return {
      id: `webhook-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp,
      event: 'generic',
      data: payload,
      signature: {
        algorithm,
        secret: '', // Never include secret in message
        timestamp,
        nonce,
        signature,
      },
    };
  }

  verifySignature(
    message: WebhookMessage,
    secret: string,
  ): { valid: boolean; error?: string } {
    const malformed = malformedReason(message);
    if (malformed) {
      return { valid: false, error: `Malformed webhook message: ${malformed}` };
    }

    const { signature } = message;

    // Verify timestamp is within replay window
    const now = Math.floor(Date.now() / 1000);
    const timeDiff = Math.abs(now - signature.timestamp);

    if (timeDiff > (this.config.maxClockSkew || 60)) {
      return { valid: false, error: 'Timestamp outside acceptable skew window' };
    }

    if (timeDiff > (this.config.replayWindowSeconds || 300)) {
      return { valid: false, error: 'Message timestamp outside replay window' };
    }

    // Verify nonce is unique
    if (this.config.nonceDeduplication && this.hasNonceBeenUsed(signature.nonce)) {
      return { valid: false, error: 'Replay attack detected: nonce already used' };
    }

    // Verify cryptographic signature with constant-time equality check
    const payloadString = JSON.stringify(message.data);
    const signingString = `${signature.timestamp}.${signature.nonce}.${payloadString}`;
    const expectedSignature = this.generateSignature(signingString, secret, signature.algorithm);

    const actualBuffer = Buffer.from(signature.signature, 'utf8');
    const expectedBuffer = Buffer.from(expectedSignature, 'utf8');

    if (
      actualBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
    ) {
      return { valid: false, error: 'Signature verification failed' };
    }

    // Record this nonce as used
    if (this.config.nonceDeduplication) {
      this.recordNonce(signature.nonce, message.timestamp, message.id);
    }

    return { valid: true };
  }

  private hasNonceBeenUsed(nonce: string): boolean {
    return this.replayRecords.has(nonce);
  }

  /**
   * Records a nonce and slides the replay window in O(1) amortized time.
   * Space complexity: O(M) bounded to MAX_REPLAY_NONCES_CAPACITY.
   */
  private recordNonce(nonce: string, timestamp: number, eventId: string): void {
    this.replayRecords.set(nonce, {
      nonce,
      timestamp,
      eventId,
      verified: true,
    });
    this.nonceQueue.push({ nonce, timestamp });

    // O(1) amortized cleanup: pop expired records from front of queue
    const cutoff = Math.floor(Date.now() / 1000) - (this.config.replayWindowSeconds || 300);
    while (this.nonceQueue.length > 0 && this.nonceQueue[0].timestamp < cutoff) {
      const expired = this.nonceQueue.shift()!;
      this.replayRecords.delete(expired.nonce);
    }

    // Bounded capacity safeguard: discard oldest if capacity exceeded
    while (this.nonceQueue.length > MAX_REPLAY_NONCES_CAPACITY) {
      const oldest = this.nonceQueue.shift()!;
      this.replayRecords.delete(oldest.nonce);
    }
  }

  /**
   * Explicit signed webhook replay-window enforcement (#355).
   *
   * Validates:
   * 1. Message structure & size boundaries
   * 2. Subscriber authorization and subscription status (if subscriberId provided)
   * 3. Future clock skew boundaries (maxClockSkew)
   * 4. Replay window freshness (replayWindowSeconds)
   * 5. Nonce deduplication in bounded sliding window
   * 6. Constant-time cryptographic HMAC verification
   *
   * Time complexity: O(1) amortized.
   * Space complexity: O(1) auxiliary.
   */
  verifyReplayWindow(
    message: WebhookMessage,
    secret: string,
    options: ReplayWindowOptions = {}
  ): ReplayWindowVerificationResult {
    // 1. Structure check
    const malformed = malformedReason(message);
    if (malformed) {
      return {
        valid: false,
        code: 'malformed_message',
        error: `Malformed webhook message: ${malformed}`
      };
    }

    // 2. Subscriber authorization check (if specified)
    if (options.subscriberId) {
      const subAuth = this.verifySubscriberAuthorization(
        options.subscriberId,
        options.expectedEvent ?? message.event,
        secret
      );
      if (!subAuth.ok) {
        const codeMap: Record<string, ReplayWindowErrorCode> = {
          subscriber_not_found: 'unauthorized_subscriber',
          inactive_subscriber: 'inactive_subscriber',
          unauthorized_event: 'unauthorized_event',
          invalid_secret: 'signature_verification_failed'
        };
        return {
          valid: false,
          code: codeMap[subAuth.code] ?? 'unauthorized_subscriber',
          error: `Subscriber authorization denied: ${subAuth.code}`
        };
      }
    }

    const { signature } = message;
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const ageSeconds = now - signature.timestamp;

    // 3. Clock skew check: rejects timestamps in future past maxClockSkew
    const maxClockSkew = this.config.maxClockSkew || 60;
    if (signature.timestamp > now + maxClockSkew) {
      return {
        valid: false,
        code: 'clock_skew_future',
        error: 'Timestamp outside acceptable skew window',
        ageSeconds
      };
    }

    // 4. Stale message check: rejects timestamps older than replay window
    const replayWindow = this.config.replayWindowSeconds || 300;
    if (signature.timestamp < now - replayWindow) {
      return {
        valid: false,
        code: 'replay_window_expired',
        error: 'Message timestamp outside replay window',
        ageSeconds
      };
    }

    // 5. Symmetric clock-skew check for backwards compatibility
    if (Math.abs(now - signature.timestamp) > maxClockSkew) {
      return {
        valid: false,
        code: 'clock_skew_future',
        error: 'Timestamp outside acceptable skew window',
        ageSeconds
      };
    }

    // 6. Nonce deduplication check
    if (this.config.nonceDeduplication && this.hasNonceBeenUsed(signature.nonce)) {
      return {
        valid: false,
        code: 'replay_attack_detected',
        error: 'Replay attack detected: nonce already used',
        ageSeconds
      };
    }

    // 7. Cryptographic signature check
    const payloadString = JSON.stringify(message.data);
    const signingString = `${signature.timestamp}.${signature.nonce}.${payloadString}`;
    const expectedSignature = this.generateSignature(signingString, secret, signature.algorithm);

    const actualBuffer = Buffer.from(signature.signature, 'utf8');
    const expectedBuffer = Buffer.from(expectedSignature, 'utf8');

    if (
      actualBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
    ) {
      return {
        valid: false,
        code: 'signature_verification_failed',
        error: 'Signature verification failed',
        ageSeconds
      };
    }

    // Record nonce in sliding window
    if (this.config.nonceDeduplication) {
      this.recordNonce(signature.nonce, message.timestamp, message.id);
    }

    return {
      valid: true,
      ageSeconds
    };
  }

  /**
   * Authorizes a subscriber for an event and secret key.
   */
  verifySubscriberAuthorization(
    subscriberId: string,
    event: string,
    secret: string
  ): Result<WebhookSubscriber, 'subscriber_not_found' | 'inactive_subscriber' | 'unauthorized_event' | 'invalid_secret'> {
    const subscriber = this.subscribers.get(subscriberId);
    if (!subscriber) {
      return err('subscriber_not_found');
    }

    if (!subscriber.active) {
      return err('inactive_subscriber');
    }

    if (!subscriber.events.includes(event) && !subscriber.events.includes('*')) {
      return err('unauthorized_event');
    }

    const secretBuffer = Buffer.from(secret, 'utf8');
    const expectedBuffer = Buffer.from(subscriber.secret, 'utf8');
    if (
      secretBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(secretBuffer, expectedBuffer)
    ) {
      return err('invalid_secret');
    }

    return ok(subscriber);
  }

  /**
   * Computes exponential backoff with jitter for delivery retries.
   */
  computeRetryBackoffMs(retryCount: number, baseDelayMs: number = 1000, maxDelayMs: number = 30000): number {
    const exponential = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, retryCount));
    const jitter = Math.floor(Math.random() * (baseDelayMs * 0.2));
    return exponential + jitter;
  }

  /**
   * Reactivates a subscriber that was quarantined due to repeated delivery failures.
   */
  reactivateSubscriber(subscriberId: string): boolean {
    const subscriber = this.subscribers.get(subscriberId);
    if (!subscriber) return false;
    subscriber.active = true;
    subscriber.failureCount = 0;
    return true;
  }

  registerSubscriber(subscriber: WebhookSubscriber): void {
    this.subscribers.set(subscriber.id, subscriber);
  }

  getSubscriber(id: string): WebhookSubscriber | undefined {
    return this.subscribers.get(id);
  }

  getActiveSubscribers(event: string): WebhookSubscriber[] {
    return Array.from(this.subscribers.values()).filter(
      s => s.active && s.events.includes(event),
    );
  }

  recordDeliveryAttempt(attempt: WebhookDeliveryAttempt): void {
    this.deliveryAttempts.push(attempt as DeliveryAttempt);

    // Update subscriber statistics
    const subscriber = this.subscribers.get(attempt.subscriberId);
    if (subscriber) {
      if (attempt.success) {
        subscriber.successCount++;
        subscriber.lastDelivery = attempt.timestamp;
      } else {
        subscriber.failureCount++;
      }
    }

    // Disable subscriber after too many failures
    if (subscriber && subscriber.failureCount > 10 && subscriber.successCount === 0) {
      subscriber.active = false;
    }
  }

  getDeliveryAttempts(subscriberId: string, limit: number = 100): WebhookDeliveryAttempt[] {
    return this.deliveryAttempts
      .filter(a => a.subscriberId === subscriberId)
      .slice(-limit);
  }

  cleanupOldRecords(olderThanSeconds: number): number {
    if (olderThanSeconds === 0) {
      const removed = this.replayRecords.size;
      this.replayRecords.clear();
      this.nonceQueue = [];
      this.deliveryAttempts = [];
      return removed;
    }

    const cutoff = Math.floor(Date.now() / 1000) - olderThanSeconds;
    let removed = 0;

    for (const [key, record] of this.replayRecords) {
      if (record.timestamp < cutoff) {
        this.replayRecords.delete(key);
        removed++;
      }
    }

    this.nonceQueue = this.nonceQueue.filter(entry => entry.timestamp >= cutoff);
    this.deliveryAttempts = this.deliveryAttempts.filter(a => {
      return a.timestamp.getTime() / 1000 >= cutoff;
    });

    return removed;
  }

  reset(): void {
    this.replayRecords.clear();
    this.nonceQueue = [];
    this.subscribers.clear();
    this.deliveryAttempts = [];
  }

  getReplayProtectionStats(): {
    totalNonces: number;
    totalDeliveryAttempts: number;
    totalSubscribers: number;
    activeSubscribers: number;
  } {
    return {
      totalNonces: this.replayRecords.size,
      totalDeliveryAttempts: this.deliveryAttempts.length,
      totalSubscribers: this.subscribers.size,
      activeSubscribers: Array.from(this.subscribers.values()).filter(s => s.active).length,
    };
  }
}

interface DeliveryAttempt extends WebhookDeliveryAttempt {}

interface WebhookRequest {
  body: {
    signature?: string;
    [key: string]: unknown;
  } | null;
}

export const webhookVerifier = new WebhookVerifier();

export function createWebhookMiddleware(verifier: WebhookVerifier) {
  return (req: WebhookRequest, secret: string) => {
    const payload = req.body;

    if (!payload || !payload.signature) {
      return { valid: false, error: 'Missing signature in payload' };
    }

    return verifier.verifySignature(payload as unknown as WebhookMessage, secret);
  };
}
