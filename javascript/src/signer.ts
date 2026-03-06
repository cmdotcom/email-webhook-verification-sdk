import { createHmac } from 'crypto';

export function generateSignature(secret: string, payload: string): string {
  const hmac = createHmac('sha512', secret);
  hmac.update(payload, 'utf8');
  return hmac.digest('base64');
}
