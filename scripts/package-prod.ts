import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const FORBIDDEN_PATTERNS = [
  /(^|\/)instance(\/|$)/i,
  /\.sqlite3?(-wal|-shm|-journal)?$/i,
  /\.(wal|shm|key|secret|pmbackup)$/i,
  /(^|\/)\.env($|\.(?!example))/i,
  /(^|\/)public\/assets(\/|$)/i,
  /\.py$/i,
  /test_candidate/i,
  /test_reference/i,
];

const EXCLUDE_DIRS = new Set([
  '.git',
  'node_modules',
  'instance',
  'dev-dist',
  'coverage',
  'release',
  'tests',
  '.aistudio',
]);

const INCLUDE_TOP_LEVEL = [
  'package.json',
  'bun.lock',
  'tsconfig.json',
  'vite.config.ts',
  'index.html',
  'metadata.json',
  'DEPLOYMENT.md',
  '.env.example',
  '.gitignore',
  'server.ts',
  'server',
  'src',
  'public',
  'scripts',
];

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

export function isForbiddenArchivePath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, '/');
  return FORBIDDEN_PATTERNS.some((re) => re.test(normalized));
}

function collectFiles(rootDir: string, relBase: string, out: string[]): void {
  const abs = path.join(rootDir, relBase);
  if (!fs.existsSync(abs)) return;
  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    const dirName = path.basename(abs);
    if (EXCLUDE_DIRS.has(dirName)) return;
    for (const entry of fs.readdirSync(abs).sort()) {
      collectFiles(rootDir, relBase ? `${relBase}/${entry}` : entry, out);
    }
  } else if (stat.isFile()) {
    const cleanRel = relBase.replace(/\\/g, '/');
    if (/\.py$/i.test(cleanRel)) return;
    if (isForbiddenArchivePath(cleanRel)) {
      throw new Error(`Refusing to package sensitive/excluded file: ${cleanRel}`);
    }
    out.push(cleanRel);
  }
}

export function createDeterministicZip(rootDir: string, outputZipPath: string): {
  files: string[];
  bytes: number;
} {
  const files: string[] = [];
  for (const item of INCLUDE_TOP_LEVEL) {
    const abs = path.join(rootDir, item);
    if (fs.existsSync(abs)) {
      collectFiles(rootDir, item, files);
    }
  }

  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const rel of files) {
    if (isForbiddenArchivePath(rel)) {
      throw new Error(`Blocked sensitive path from production ZIP: ${rel}`);
    }
    const raw = fs.readFileSync(path.join(rootDir, rel));
    const compressed = zlib.deflateRawSync(raw);
    const crc = crc32(raw);
    const nameBuf = Buffer.from(rel, 'utf8');

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0x0800, 6); // UTF-8
    localHeader.writeUInt16LE(8, 8); // deflate
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0x5421, 12); // fixed DOS date
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(raw.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0x5421, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(raw.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    localParts.push(localHeader, nameBuf, compressed);
    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }

  const centralDirBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  const zipBuf = Buffer.concat([...localParts, centralDirBuf, eocd]);
  fs.mkdirSync(path.dirname(outputZipPath), { recursive: true });
  fs.writeFileSync(outputZipPath, zipBuf);
  return { files, bytes: zipBuf.length };
}

export function listZipEntryNames(zipPath: string): string[] {
  const buf = fs.readFileSync(zipPath);
  const names: string[] = [];
  // Locate End of Central Directory
  let eocdOffset = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65558); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) throw new Error('Invalid ZIP file (missing EOCD).');
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);
  const totalEntries = buf.readUInt16LE(eocdOffset + 10);
  let pos = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (buf.readUInt32LE(pos) !== 0x02014b50) {
      throw new Error('Corrupt central directory in ZIP archive.');
    }
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const name = buf.subarray(pos + 46, pos + 46 + nameLen).toString('utf8');
    names.push(name);
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rootDir = process.cwd();
  const outPath = path.resolve(rootDir, 'release/privacy-monitor-prod.zip');
  const res = createDeterministicZip(rootDir, outPath);
  const verified = listZipEntryNames(outPath);
  for (const name of verified) {
    if (isForbiddenArchivePath(name)) {
      fs.unlinkSync(outPath);
      throw new Error(`Security check failed: forbidden file detected in archive: ${name}`);
    }
  }
  console.log(`Created clean production archive ${outPath} (${res.files.length} files, ${res.bytes} bytes).`);
}
