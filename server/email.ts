import crypto from 'node:crypto';

export function generateEmailOTP(): string {
  return crypto.randomInt(0, 1000000)
    .toString()
    .padStart(6, '0');
}

export function isEmailConfigured(): boolean {
  return Boolean(
    process.env.RESEND_API_KEY?.trim() &&
    process.env.MAIL_FROM?.trim()
  );
}

export async function sendVerificationEmail(
  email: string,
  otp: string
): Promise<void> {
  if (!isEmailConfigured()) {
    throw new Error('Email delivery is not configured.');
  }

  const response = await fetch(
    'https://api.resend.com/emails',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(15000),
      body: JSON.stringify({
        from: process.env.MAIL_FROM,
        to: [email],
        subject: 'Privacy Monitor - Verification Code',
        html: `
          <h2>Privacy Monitor</h2>
          <p>Your email verification code is:</p>
          <h1 style="letter-spacing:8px">${otp}</h1>
          <p>This code expires in 5 minutes.</p>
          <p>Do not share this code with anyone.</p>
          <p>If you did not request this code,
          ignore this email.</p>
        `,
        text: `Your Privacy Monitor verification code is ${otp}. It expires in 5 minutes.`,
      }),
    }
  );

  if (!response.ok) {
    throw new Error(
      `Email delivery failed (HTTP ${response.status}).`
    );
  }
}
