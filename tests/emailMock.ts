const deliveredCodes = new Map<string, string>();

export function installEmailMock(): () => void {
  const originalFetch = globalThis.fetch;
  const originalKey = process.env.RESEND_API_KEY;
  const originalFrom = process.env.MAIL_FROM;

  process.env.RESEND_API_KEY = 'test-only-key';
  process.env.MAIL_FROM = 'test@example.org';

  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;

    if (url === 'https://api.resend.com/emails') {
      const body = JSON.parse(String(init?.body || '{}'));

      const email = Array.isArray(body.to)
        ? String(body.to[0])
        : String(body.to);

      const match = String(body.text || '')
        .match(/\b\d{6}\b/);

      if (!match) {
        return new Response(
          JSON.stringify({ error: 'OTP missing' }),
          { status: 400 }
        );
      }

      deliveredCodes.set(
        email.trim().toLowerCase(),
        match[0]
      );

      return new Response(
        JSON.stringify({ id: 'test-email-delivery' }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
    }

    return originalFetch(input, init);
  };

  return () => {
    globalThis.fetch = originalFetch;
    deliveredCodes.clear();

    if (originalKey === undefined) {
      delete process.env.RESEND_API_KEY;
    } else {
      process.env.RESEND_API_KEY = originalKey;
    }

    if (originalFrom === undefined) {
      delete process.env.MAIL_FROM;
    } else {
      process.env.MAIL_FROM = originalFrom;
    }
  };
}

export function getDeliveredOTP(email: string): string {
  const otp = deliveredCodes.get(
    email.trim().toLowerCase()
  );

  if (!otp) {
    throw new Error('No test OTP delivered');
  }

  return otp;
}
