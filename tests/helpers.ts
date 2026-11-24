import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

// Isolate every test worker completely away from the live instance directory
export const TEST_INSTANCE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-test-'));
process.env.PRIVACY_INSTANCE_DIR = TEST_INSTANCE_DIR;
process.env.PRIVACY_DB_PATH = path.join(TEST_INSTANCE_DIR, 'test.sqlite3');
process.env.DISABLE_SCHEDULER = 'true';
// Clear inherited reviewer env passcode by default unless a test explicitly tests REVIEWER_PASSCODE
delete process.env.REVIEWER_PASSCODE;
delete process.env.REVIEWER_BOOTSTRAP_TOKEN;

export function cleanupTestInstance(): void {
  fs.rmSync(TEST_INSTANCE_DIR, { recursive: true, force: true });
}

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      const mask = -(crc & 1);
      crc = (crc >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

export function makeValidPngBuffer(r = 30, g = 90, b = 150): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(2, 0); // width 2
  ihdr.writeUInt32BE(2, 4); // height 2
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  // 2 rows, each filter byte 0 + 2 RGB pixels
  const raw = Buffer.from([
    0, r, g, b, r, g, b,
    0, r, g, b, r, g, b,
  ]);
  const idat = zlib.deflateSync(raw);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', idat),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

export function makeValidPngDataUrl(r = 30, g = 90, b = 150): string {
  return `data:image/png;base64,${makeValidPngBuffer(r, g, b).toString('base64')}`;
}

export async function startIsolatedServer(isProd = false): Promise<{
  baseUrl: string;
  port: number;
  close: () => Promise<void>;
}> {
  const { createApp } = await import('../server/app.ts');
  const app = await createApp({ isProd, skipVite: true });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Failed to bind ephemeral test port.');
  }
  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    port: addr.port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

export async function apiFetch(
  baseUrl: string,
  pathname: string,
  opts: {
    method?: string;
    body?: unknown;
    token?: string;
    reviewerToken?: string;
    headers?: Record<string, string>;
  } = {}
) {
  const headers: Record<string, string> = { ...(opts.headers || {}) };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.reviewerToken) headers['X-Reviewer-Token'] = opts.reviewerToken;

  const res = await fetch(`${baseUrl}${pathname}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json')
    ? await res.json()
    : Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, data };
}
