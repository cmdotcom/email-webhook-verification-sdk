import { timingSafeEqual } from 'crypto';
import { generateSignature } from './signer';
import { HEADERS, DEFAULT_TOLERANCE_SECONDS } from './constants';
import {
  MissingHeadersError,
  InvalidSignatureError,
  InvalidTimestampError,
  TimestampExpiredError,
} from './errors';

export type WebhookHeaders = Record<string, string | string[] | undefined> | Map<string, string>;

export interface WebhookValidatorOptions {
  secretKey: string;
  toleranceInSeconds?: number;
}

export class WebhookValidator {
  private readonly secretKey: string;
  private readonly toleranceMs: number;

  constructor(options: WebhookValidatorOptions) {
    const { secretKey, toleranceInSeconds = DEFAULT_TOLERANCE_SECONDS } = options;

    if (!secretKey || secretKey.trim() === '') {
      throw new Error('secretKey cannot be empty');
    }

    this.secretKey = secretKey;
    this.toleranceMs = toleranceInSeconds * 1000;
  }

  verify<T = unknown>(payload: string, headers: WebhookHeaders): T {
    const id = this.getHeader(headers, HEADERS.ID);
    const timestampStr = this.getHeader(headers, HEADERS.TIMESTAMP);
    const signature = this.getHeader(headers, HEADERS.SIGNATURE);

    const missingHeaders: string[] = [];
    if (!id) missingHeaders.push(HEADERS.ID);
    if (!timestampStr) missingHeaders.push(HEADERS.TIMESTAMP);
    if (!signature) missingHeaders.push(HEADERS.SIGNATURE);

    if (missingHeaders.length > 0) {
      throw new MissingHeadersError(missingHeaders);
    }

    const timestampMs = parseInt(timestampStr!, 10);
    if (isNaN(timestampMs)) {
      throw new InvalidTimestampError();
    }

    const currentMs = Date.now();
    const diff = Math.abs(currentMs - timestampMs);

    if (diff > this.toleranceMs) {
      throw new TimestampExpiredError();
    }

    const signaturePayload = `${id}.${timestampMs}.${payload}`;

    const expectedSignature = generateSignature(this.secretKey, signaturePayload);

    if (!this.constantTimeCompare(expectedSignature, signature!)) {
      throw new InvalidSignatureError();
    }

    return JSON.parse(payload) as T;
  }

  private getHeader(headers: WebhookHeaders, name: string): string | undefined {
    if (headers instanceof Map) {
      return headers.get(name);
    }

    const value = headers[name] ?? headers[name.toLowerCase()];
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }

  private constantTimeCompare(a: string, b: string): boolean {
    try {
      const bufA = Buffer.from(a, 'base64');
      const bufB = Buffer.from(b, 'base64');

      if (bufA.length !== bufB.length) {
        return false;
      }

      return timingSafeEqual(bufA, bufB);
    } catch {
      return false;
    }
  }
}
