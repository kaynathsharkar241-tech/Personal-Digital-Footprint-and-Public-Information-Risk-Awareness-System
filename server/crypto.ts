import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const INSTANCE_DIR = process.env.PRIVACY_INSTANCE_DIR
  ? path.resolve(process.env.PRIVACY_INSTANCE_DIR)
  : path.resolve(process.cwd(), 'instance');
const KEY_PATH = path.join(INSTANCE_DIR, 'evidence.key');

function loadOrCreateMasterKey(): Buffer {
  const envKey = process.env.EVIDENCE_KEY?.trim();
  if (envKey) {
    const buf = Buffer.from(envKey, 'base64');
    if (buf.length === 32) return buf;
    return crypto.createHash('sha256').update(envKey).digest();
  }
  fs.mkdirSync(INSTANCE_DIR, { recursive: true });
  if (fs.existsSync(KEY_PATH)) {
    const raw = fs.readFileSync(KEY_PATH, 'utf8').trim();
    const buf = Buffer.from(raw, 'base64');
    if (buf.length === 32) return buf;
  }
  const generated = crypto.randomBytes(32);
  fs.writeFileSync(KEY_PATH, generated.toString('base64'), { mode: 0o600 });
  return generated;
}

const MASTER_KEY = loadOrCreateMasterKey();
const SESSION_SECRET_PATH = path.join(INSTANCE_DIR, 'session.secret');

export function loadOrCreateSessionSecret(): string {
  const envSecret = process.env.SESSION_SECRET?.trim();
  if (envSecret) {
    if (envSecret.length < 32) {
      throw new Error('SESSION_SECRET environment override must be at least 32 characters.');
    }
    return envSecret;
  }
  fs.mkdirSync(INSTANCE_DIR, { recursive: true });
  if (fs.existsSync(SESSION_SECRET_PATH)) {
    const existing = fs.readFileSync(SESSION_SECRET_PATH, 'utf8').trim();
    if (existing.length >= 64) {
      process.env.SESSION_SECRET = existing;
      return existing;
    }
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SESSION_SECRET_PATH, generated, { mode: 0o600 });
  process.env.SESSION_SECRET = generated;
  return generated;
}

export function getMasterKeyLength(): number {
  return MASTER_KEY.length;
}


export function encryptBuffer(plaintext: Buffer): {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
} {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { encrypted, iv, authTag };
}

export function decryptBuffer(
  encrypted: Buffer | Uint8Array,
  iv: Buffer | Uint8Array,
  authTag: Buffer | Uint8Array
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(iv));
  decipher.setAuthTag(Buffer.from(authTag));
  return Buffer.concat([decipher.update(Buffer.from(encrypted)), decipher.final()]);
}

export function hashSecret(secret: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(secret, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifySecret(secret: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  const derived = crypto.scryptSync(secret, salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function generateToken(byteLength = 32): { raw: string; hash: string } {
  const raw = crypto.randomBytes(byteLength).toString('base64url');
  return { raw, hash: sha256Hex(raw) };
}

export function generateRecoveryCodes(count = 8): Array<{ plain: string; hash: string }> {
  const codes: Array<{ plain: string; hash: string }> = [];
  for (let i = 0; i < count; i++) {
    const partA = crypto.randomBytes(2).toString('hex').toUpperCase();
    const partB = crypto.randomBytes(2).toString('hex').toUpperCase();
    const plain = `PM-${partA}-${partB}`;
    codes.push({ plain, hash: sha256Hex(plain) });
  }
  return codes;
}
