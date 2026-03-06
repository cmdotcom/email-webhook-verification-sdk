import { generateSignature } from '../src/signer';

describe('generateSignature', () => {
  it('should generate deterministic signatures', () => {
    const sig1 = generateSignature('secret', 'payload');
    const sig2 = generateSignature('secret', 'payload');
    expect(sig1).toBe(sig2);
  });

  it('should generate different signatures for different secrets', () => {
    const sig1 = generateSignature('secret1', 'payload');
    const sig2 = generateSignature('secret2', 'payload');
    expect(sig1).not.toBe(sig2);
  });

  it('should generate different signatures for different payloads', () => {
    const sig1 = generateSignature('secret', 'payload1');
    const sig2 = generateSignature('secret', 'payload2');
    expect(sig1).not.toBe(sig2);
  });

  it('should generate valid base64 signatures', () => {
    const sig = generateSignature('secret', 'payload');
    expect(() => Buffer.from(sig, 'base64')).not.toThrow();
  });

  it('should generate 64-byte SHA512 hashes', () => {
    const sig = generateSignature('secret', 'payload');
    const decoded = Buffer.from(sig, 'base64');
    expect(decoded.length).toBe(64);
  });
});
