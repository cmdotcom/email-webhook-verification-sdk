import {
  WebhookValidator,
  generateSignature,
  MissingHeadersError,
  InvalidSignatureError,
  InvalidTimestampError,
  TimestampExpiredError,
} from '../src';

const TEST_SECRET = 'test-secret-key';

interface TestPayload {
  event: string;
  data: string;
}

function createValidHeaders(
  secret: string,
  payload: string,
  timestampMs: number
): Record<string, string> {
  const messageId = 'msg-123';
  const signaturePayload = `${messageId}.${timestampMs}.${payload}`;
  const signature = generateSignature(secret, signaturePayload);

  return {
    'svix-id': messageId,
    'svix-timestamp': timestampMs.toString(),
    'svix-signature': signature,
  };
}

describe('WebhookValidator', () => {
  describe('constructor', () => {
    it('should create validator with default tolerance', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      expect(validator).toBeInstanceOf(WebhookValidator);
    });

    it('should create validator with custom tolerance', () => {
      const validator = new WebhookValidator({
        secretKey: TEST_SECRET,
        toleranceInSeconds: 60,
      });
      expect(validator).toBeInstanceOf(WebhookValidator);
    });

    it('should throw error for empty secret key', () => {
      expect(() => new WebhookValidator({ secretKey: '' })).toThrow(
        'secretKey cannot be empty'
      );
    });

    it('should throw error for whitespace secret key', () => {
      expect(() => new WebhookValidator({ secretKey: '   ' })).toThrow(
        'secretKey cannot be empty'
      );
    });
  });

  describe('verify', () => {
    it('should verify valid webhook', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';
      const timestampMs = Date.now();
      const headers = createValidHeaders(TEST_SECRET, payload, timestampMs);

      const result = validator.verify<TestPayload>(payload, headers);
      expect(result.event).toBe('test');
      expect(result.data).toBe('hello');
    });

    it('should reject invalid signature', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';
      const timestampMs = Date.now();
      const headers = createValidHeaders('wrong-secret', payload, timestampMs);

      expect(() => validator.verify<TestPayload>(payload, headers)).toThrow(
        InvalidSignatureError
      );
    });

    it('should throw MissingHeadersError for missing svix-id', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test"}';
      const headers = {
        'svix-timestamp': '123456',
        'svix-signature': 'sig',
      };

      try {
        validator.verify(payload, headers);
        fail('Expected MissingHeadersError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingHeadersError);
        expect((error as MissingHeadersError).missingHeaders).toContain('svix-id');
      }
    });

    it('should throw MissingHeadersError for missing svix-timestamp', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test"}';
      const headers = {
        'svix-id': 'msg-123',
        'svix-signature': 'sig',
      };

      try {
        validator.verify(payload, headers);
        fail('Expected MissingHeadersError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingHeadersError);
        expect((error as MissingHeadersError).missingHeaders).toContain(
          'svix-timestamp'
        );
      }
    });

    it('should throw MissingHeadersError for missing svix-signature', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test"}';
      const headers = {
        'svix-id': 'msg-123',
        'svix-timestamp': '123456',
      };

      try {
        validator.verify(payload, headers);
        fail('Expected MissingHeadersError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingHeadersError);
        expect((error as MissingHeadersError).missingHeaders).toContain(
          'svix-signature'
        );
      }
    });

    it('should list all missing headers', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test"}';
      const headers = {};

      try {
        validator.verify(payload, headers);
        fail('Expected MissingHeadersError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingHeadersError);
        const missing = (error as MissingHeadersError).missingHeaders;
        expect(missing).toContain('svix-id');
        expect(missing).toContain('svix-timestamp');
        expect(missing).toContain('svix-signature');
      }
    });

    it('should throw InvalidTimestampError for invalid timestamp format', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test"}';
      const headers = {
        'svix-id': 'msg-123',
        'svix-timestamp': 'not-a-number',
        'svix-signature': 'sig',
      };

      expect(() => validator.verify(payload, headers)).toThrow(
        InvalidTimestampError
      );
    });

    it('should throw TimestampExpiredError for expired timestamp', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';

      const oldTimestamp = Date.now() - 10 * 60 * 1000;
      const headers = createValidHeaders(TEST_SECRET, payload, oldTimestamp);

      expect(() => validator.verify<TestPayload>(payload, headers)).toThrow(
        TimestampExpiredError
      );
    });

    it('should accept future timestamp within tolerance', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';

      const futureTimestamp = Date.now() + 2 * 60 * 1000;
      const headers = createValidHeaders(TEST_SECRET, payload, futureTimestamp);

      const result = validator.verify<TestPayload>(payload, headers);
      expect(result.event).toBe('test');
    });

    it('should reject future timestamp outside tolerance', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';

      const futureTimestamp = Date.now() + 10 * 60 * 1000;
      const headers = createValidHeaders(TEST_SECRET, payload, futureTimestamp);

      expect(() => validator.verify<TestPayload>(payload, headers)).toThrow(
        TimestampExpiredError
      );
    });

    it('should respect custom tolerance', () => {
      const validator = new WebhookValidator({
        secretKey: TEST_SECRET,
        toleranceInSeconds: 1,
      });
      const payload = '{"event":"test","data":"hello"}';

      const oldTimestamp = Date.now() - 5000;
      const headers = createValidHeaders(TEST_SECRET, payload, oldTimestamp);

      expect(() => validator.verify<TestPayload>(payload, headers)).toThrow(
        TimestampExpiredError
      );
    });

    it('should work with Map headers', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';
      const timestampMs = Date.now();

      const messageId = 'msg-123';
      const signaturePayload = `${messageId}.${timestampMs}.${payload}`;
      const signature = generateSignature(TEST_SECRET, signaturePayload);

      const headers = new Map<string, string>([
        ['svix-id', messageId],
        ['svix-timestamp', timestampMs.toString()],
        ['svix-signature', signature],
      ]);

      const result = validator.verify<TestPayload>(payload, headers);
      expect(result.event).toBe('test');
    });

    it('should work with array header values', () => {
      const validator = new WebhookValidator({ secretKey: TEST_SECRET });
      const payload = '{"event":"test","data":"hello"}';
      const timestampMs = Date.now();

      const messageId = 'msg-123';
      const signaturePayload = `${messageId}.${timestampMs}.${payload}`;
      const signature = generateSignature(TEST_SECRET, signaturePayload);

      const headers: Record<string, string | string[]> = {
        'svix-id': [messageId],
        'svix-timestamp': [timestampMs.toString()],
        'svix-signature': [signature],
      };

      const result = validator.verify<TestPayload>(payload, headers);
      expect(result.event).toBe('test');
    });
  });
});
