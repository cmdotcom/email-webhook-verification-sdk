export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebhookVerificationError';
    Object.setPrototypeOf(this, WebhookVerificationError.prototype);
  }
}

export class MissingHeadersError extends WebhookVerificationError {
  public readonly missingHeaders: string[];

  constructor(headers: string[]) {
    super(`Missing required header(s): ${headers.join(', ')}`);
    this.name = 'MissingHeadersError';
    this.missingHeaders = headers;
    Object.setPrototypeOf(this, MissingHeadersError.prototype);
  }
}

export class InvalidSignatureError extends WebhookVerificationError {
  constructor() {
    super('Invalid signature');
    this.name = 'InvalidSignatureError';
    Object.setPrototypeOf(this, InvalidSignatureError.prototype);
  }
}

export class InvalidTimestampError extends WebhookVerificationError {
  constructor() {
    super('Invalid timestamp format');
    this.name = 'InvalidTimestampError';
    Object.setPrototypeOf(this, InvalidTimestampError.prototype);
  }
}

export class TimestampExpiredError extends WebhookVerificationError {
  constructor() {
    super('Webhook timestamp is outside the allowed tolerance window');
    this.name = 'TimestampExpiredError';
    Object.setPrototypeOf(this, TimestampExpiredError.prototype);
  }
}
