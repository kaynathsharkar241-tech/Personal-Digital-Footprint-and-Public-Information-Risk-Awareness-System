import { formatFindingPriority, formatFindingRisk } from '../src/utils/findingPresentation.ts';
/**
 * Pure TypeScript PDF 1.4 Report Generator (zero external native binaries or paid services).
 * Produces compliant multi-page PDF documents with standard Helvetica / Courier Type1 fonts.
 */

export interface PdfFindingRow {
  id: number;
  title: string;
  category: string;
  source_name: string;
  source: string;
  found_at: string;
  risk: string;
  evidence: string;
  confidence: number;
  priority: number;
  verification_status: string;
  review_note: string;
}

export interface PdfCaseRow {
  id: number;
  title: string;
  category: string;
  description: string;
  url: string;
  status: string;
  notes: string;
  resolution_summary: string;
  created_at: string;
  resolved_at: string | null;
  evidenceCount: number;
}

export interface PdfEvidenceRow {
  id: number;
  name: string;
  mime: string;
  created_at: string;
}

export interface PdfCaseEventRow {
  event_type: string;
  status: string;
  summary: string;
  created_at: string;
}

const PAGE_WIDTH = 612; // US Letter 8.5in
const PAGE_HEIGHT = 792; // US Letter 11in
const MARGIN_X = 48;
const TOP_Y = 744;
const BOTTOM_Y = 54;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN_X * 2;

export function sanitizePdfText(input: unknown): string {
  return String(input ?? '')
    .replace(/\r?\n/g, ' ')
    .replace(/\t/g, '  ')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/\u2022/g, '*')
    .replace(/\u2192/g, '->')
    .replace(/[^\x20-\x7E]/g, '?');
}

function escapePdfString(text: string): string {
  return sanitizePdfText(text)
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrapText(text: string, maxChars: number): string[] {
  const clean = sanitizePdfText(text).trim();
  if (!clean) return [];
  const words = clean.split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (word.length > maxChars) {
      if (current) {
        lines.push(current);
        current = '';
      }
      for (let i = 0; i < word.length; i += maxChars) {
        lines.push(word.slice(i, i + maxChars));
      }
      continue;
    }
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length <= maxChars) {
      current = candidate;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

type FontAlias = 'F1' | 'F2' | 'F3';

class PdfCanvasBuilder {
  private pages: string[][] = [[]];
  private y = TOP_Y;
  private readonly docTitle: string;
  private readonly generatedAt: string;

  constructor(docTitle: string, generatedAt: string) {
    this.docTitle = sanitizePdfText(docTitle);
    this.generatedAt = sanitizePdfText(generatedAt);
  }

  private get cur(): string[] {
    return this.pages[this.pages.length - 1];
  }

  private ensureSpace(neededHeight: number) {
    if (this.y - neededHeight < BOTTOM_Y) {
      this.pages.push([]);
      this.y = TOP_Y;
    }
  }

  addBanner(title: string, subtitle: string) {
    this.ensureSpace(64);
    const barHeight = 52;
    const rectY = this.y - barHeight + 12;
    this.cur.push(
      `0.082 0.224 0.353 rg ${MARGIN_X} ${rectY} ${CONTENT_WIDTH} ${barHeight} re f`
    );
    this.cur.push(
      `1 1 1 rg BT /F2 15 Tf ${MARGIN_X + 14} ${this.y - 6} Td (${escapePdfString(title)}) Tj ET`
    );
    this.cur.push(
      `0.85 0.90 0.96 rg BT /F1 9 Tf ${MARGIN_X + 14} ${this.y - 23} Td (${escapePdfString(subtitle)}) Tj ET`
    );
    this.cur.push('0 0 0 rg');
    this.y -= barHeight + 14;
  }

  addSectionHeading(heading: string) {
    this.ensureSpace(32);
    this.y -= 6;
    this.cur.push(
      `0.082 0.224 0.353 rg BT /F2 12 Tf ${MARGIN_X} ${this.y} Td (${escapePdfString(heading)}) Tj ET`
    );
    this.cur.push(
      `0.82 0.85 0.89 RG 0.7 w ${MARGIN_X} ${this.y - 5} m ${PAGE_WIDTH - MARGIN_X} ${this.y - 5} l S`
    );
    this.cur.push('0 0 0 rg 0 0 0 RG');
    this.y -= 20;
  }

  addParagraph(text: string, options?: { font?: FontAlias; size?: number; indent?: number; color?: string }) {
    const font = options?.font ?? 'F1';
    const size = options?.size ?? 9.5;
    const indent = options?.indent ?? 0;
    const color = options?.color ?? '0.15 0.18 0.24';
    const lineHeight = Math.round((size + 4) * 10) / 10;
    const avgCharWidth = font === 'F3' ? size * 0.6 : size * 0.5;
    const maxChars = Math.max(24, Math.floor((CONTENT_WIDTH - indent) / avgCharWidth));
    const lines = wrapText(text, maxChars);

    for (const line of lines) {
      this.ensureSpace(lineHeight + 2);
      this.cur.push(
        `${color} rg BT /${font} ${size} Tf ${MARGIN_X + indent} ${this.y} Td (${escapePdfString(line)}) Tj ET`
      );
      this.y -= lineHeight;
    }
    this.cur.push('0 0 0 rg');
  }

  addKeyValue(label: string, value: string, indent = 0) {
    this.addParagraph(`${label}: ${value}`, { font: 'F1', size: 9.5, indent });
  }

  addSpacer(height = 8) {
    this.ensureSpace(height);
    this.y -= height;
  }

  addDivider() {
    this.ensureSpace(10);
    this.cur.push(
      `0.88 0.90 0.93 RG 0.5 w ${MARGIN_X} ${this.y} m ${PAGE_WIDTH - MARGIN_X} ${this.y} l S 0 0 0 RG`
    );
    this.y -= 10;
  }

  build(): Buffer {
    const totalPages = this.pages.length;
    const objects: string[] = [];

    const addObj = (body: string): number => {
      objects.push(body);
      return objects.length;
    };

    // 1: Catalog (placeholder updated below), 2: Pages (placeholder), 3..5: Fonts
    const catalogId = addObj('');
    const pagesId = addObj('');
    const fontRegularId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    const fontBoldId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    const fontMonoId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');

    const pageIds: number[] = [];
    for (let i = 0; i < totalPages; i++) {
      const pageLines = [...this.pages[i]];
      // Footer on every page
      pageLines.push(
        `0.82 0.85 0.89 RG 0.5 w ${MARGIN_X} 36 m ${PAGE_WIDTH - MARGIN_X} 36 l S`
      );
      pageLines.push(
        `0.42 0.46 0.52 rg BT /F1 8 Tf ${MARGIN_X} 24 Td (${escapePdfString(
          `${this.docTitle} | Generated ${this.generatedAt}`
        )}) Tj ET`
      );
      const pageNumLabel = `Page ${i + 1} of ${totalPages}`;
      pageLines.push(
        `0.42 0.46 0.52 rg BT /F1 8 Tf ${PAGE_WIDTH - MARGIN_X - 65} 24 Td (${escapePdfString(
          pageNumLabel
        )}) Tj ET`
      );

      const streamStr = pageLines.join('\n');
      const streamBytes = Buffer.byteLength(streamStr, 'latin1');
      const contentId = addObj(`<< /Length ${streamBytes} >>\nstream\n${streamStr}\nendstream`);
      const pageId = addObj(
        `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R /F3 ${fontMonoId} 0 R >> >> /Contents ${contentId} 0 R >>`
      );
      pageIds.push(pageId);
    }

    objects[catalogId - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
    objects[pagesId - 1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;

    const chunks: Buffer[] = [Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'latin1')];
    const offsets: number[] = [0];
    let byteOffset = chunks[0].length;

    for (let i = 0; i < objects.length; i++) {
      offsets.push(byteOffset);
      const objBuf = Buffer.from(`${i + 1} 0 obj\n${objects[i]}\nendobj\n`, 'latin1');
      chunks.push(objBuf);
      byteOffset += objBuf.length;
    }

    const xrefOffset = byteOffset;
    const xrefLines = [`xref`, `0 ${objects.length + 1}`, `0000000000 65535 f `];
    for (let i = 1; i <= objects.length; i++) {
      xrefLines.push(`${String(offsets[i]).padStart(10, '0')} 00000 n `);
    }
    const trailer = [
      `trailer`,
      `<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>`,
      `startxref`,
      String(xrefOffset),
      `%%EOF\n`,
    ].join('\n');

    chunks.push(Buffer.from(`${xrefLines.join('\n')}\n${trailer}`, 'latin1'));
    return Buffer.concat(chunks);
  }
}

export function buildAccountReportPdf(params: {
  userName: string;
  userEmail: string;
  emailVerified: boolean;
  selfieStatus: string;
  exposureScore: number | null;
  generatedAt: string;
  findings: PdfFindingRow[];
  cases: PdfCaseRow[];
}): Buffer {
  const doc = new PdfCanvasBuilder('Privacy Monitor Exposure & Case Report', params.generatedAt);

  doc.addBanner(
    'Privacy Monitor - Digital Footprint & Case Report',
    `Account: ${params.userName} (${params.userEmail}) | Generated: ${params.generatedAt}`
  );

  doc.addSectionHeading('1. Executive Summary');
  doc.addKeyValue(
    'Identity Verification',
    `Email ${params.emailVerified ? 'Verified' : 'Unverified'} | Enrollment Selfie: ${params.selfieStatus}`
  );
  doc.addKeyValue(
    'Exposure Questionnaire Index',
    params.exposureScore === null ? 'Not assessed yet' : `${params.exposureScore} / 100`
  );

  const verifiedMatches = params.findings.filter((f) => f.verification_status === 'Verified Match');
  const safeLibrary = params.findings.filter((f) => f.verification_status === 'False Positive');

  doc.addKeyValue(
    'Findings Overview',
    `${params.findings.length} total | ${verifiedMatches.length} Verified Match | ${safeLibrary.length} False Positive | ${params.findings.length - verifiedMatches.length - safeLibrary.length} Potential Match`
  );

  const resolvedCases = params.cases.filter((c) => c.status === 'Resolved').length;
  doc.addKeyValue(
    'Misuse Cases Overview',
    `${params.cases.length} total (${params.cases.length - resolvedCases} Active, ${resolvedCases} Resolved)`
  );

  doc.addSectionHeading(`2. Discovered OSINT Findings (${params.findings.length})`);
  if (params.findings.length === 0) {
    doc.addParagraph('No OSINT findings recorded yet for this account.');
  } else {
    for (const f of params.findings) {
      doc.addParagraph(`[#${f.id}] ${f.title}`, { font: 'F2', size: 10, color: '0.06 0.09 0.16' });
      doc.addParagraph(
        `Category: ${f.category} | Risk: ${formatFindingRisk(f.risk, f.verification_status)} | Status: ${f.verification_status} | Priority: ${formatFindingPriority(f.priority, f.verification_status)}`,
        { size: 8.5, indent: 8, color: '0.28 0.33 0.41' }
      );
      doc.addParagraph(`Source: ${f.source_name || 'External OSINT'} | URL: ${f.source}`, {
        font: 'F3',
        size: 8.2,
        indent: 8,
        color: '0.20 0.25 0.33',
      });
      doc.addParagraph(`Retrieved: ${f.found_at}`, {
        font: 'F3',
        size: 8.2,
        indent: 8,
        color: '0.28 0.33 0.41',
      });
      if (f.evidence) {
        doc.addParagraph(`Evidence: ${f.evidence.slice(0, 350)}`, { size: 8.5, indent: 8 });
      }
      if (f.review_note) {
        doc.addParagraph(`Review Note: ${f.review_note}`, { size: 8.5, indent: 8 });
      }
      doc.addSpacer(5);
    }
  }

  doc.addSectionHeading(`3. Misuse Cases & Resolution Tracking (${params.cases.length})`);
  if (params.cases.length === 0) {
    doc.addParagraph('No misuse cases logged yet.');
  } else {
    for (const c of params.cases) {
      doc.addParagraph(`Case #${c.id}: ${c.title} [${c.status}]`, {
        font: 'F2',
        size: 10,
        color: '0.06 0.09 0.16',
      });
      doc.addParagraph(
        `Category: ${c.category} | Opened: ${c.created_at}${
          c.resolved_at ? ` | Resolved: ${c.resolved_at}` : ''
        } | Encrypted Evidence Files: ${c.evidenceCount}`,
        { size: 8.5, indent: 8, color: '0.28 0.33 0.41' }
      );
      if (c.url) {
        doc.addParagraph(`Reference URL: ${c.url}`, { font: 'F3', size: 8.2, indent: 8 });
      }
      doc.addParagraph(`Description: ${c.description.slice(0, 400)}`, { size: 8.5, indent: 8 });
      if (c.resolution_summary) {
        doc.addParagraph(`Resolution Summary: ${c.resolution_summary}`, { size: 8.5, indent: 8 });
      }
      if (c.notes) {
        doc.addParagraph(`Investigation Notes: ${c.notes.slice(0, 300)}`, { size: 8.5, indent: 8 });
      }
      doc.addSpacer(5);
    }
  }

  return doc.build();
}

export function buildCaseDossierPdf(params: {
  userName: string;
  userEmail: string;
  generatedAt: string;
  caseItem: PdfCaseRow;
  evidence: PdfEvidenceRow[];
  timeline: PdfCaseEventRow[];
}): Buffer {
  const { caseItem } = params;
  const doc = new PdfCanvasBuilder(`Privacy Monitor Case #${caseItem.id}`, params.generatedAt);

  doc.addBanner(
    `Incident Dossier - Case #${caseItem.id}`,
    `Owner: ${params.userName} (${params.userEmail}) | Status: ${caseItem.status}`
  );

  doc.addSectionHeading('1. Case Metadata & Description');
  doc.addKeyValue('Title', caseItem.title);
  doc.addKeyValue('Category', caseItem.category);
  doc.addKeyValue('Status', caseItem.status);
  doc.addKeyValue('Opened At', caseItem.created_at);
  doc.addKeyValue('Resolved At', caseItem.resolved_at || 'Not yet resolved');
  if (caseItem.url) doc.addKeyValue('Reference URL', caseItem.url);
  doc.addSpacer(4);
  doc.addParagraph(caseItem.description);

  if (caseItem.resolution_summary || caseItem.notes) {
    doc.addSectionHeading('2. Investigation & Resolution Details');
    if (caseItem.resolution_summary) {
      doc.addKeyValue('Resolution Summary', caseItem.resolution_summary);
    }
    if (caseItem.notes) {
      doc.addParagraph(`Investigation Notes: ${caseItem.notes}`);
    }
  }

  doc.addSectionHeading(`3. Encrypted Evidence Manifest (${params.evidence.length})`);
  if (params.evidence.length === 0) {
    doc.addParagraph('No encrypted evidence attachments on this case.');
  } else {
    for (const ev of params.evidence) {
      doc.addParagraph(
        `- [Evidence #${ev.id}] ${ev.name} (${ev.mime}) - Stored AES-256-GCM at ${ev.created_at}`,
        { font: 'F3', size: 8.5, indent: 6 }
      );
    }
  }

  doc.addSectionHeading(`4. Case Audit Timeline (${params.timeline.length})`);
  if (params.timeline.length === 0) {
    doc.addParagraph('No timeline events recorded yet.');
  } else {
    for (const evt of params.timeline) {
      doc.addParagraph(
        `${evt.created_at} [${evt.status}] ${evt.event_type}: ${evt.summary}`,
        { size: 8.5, indent: 6 }
      );
    }
  }

  return doc.build();
}
