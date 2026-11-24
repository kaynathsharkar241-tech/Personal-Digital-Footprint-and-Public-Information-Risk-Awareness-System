import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import {
  apiFetch,
  cleanupTestInstance,
  makeValidPngDataUrl,
  startIsolatedServer,
} from './helpers.ts';

// Minimal deterministic CBOR encoder for WebAuthn software authenticator test fixtures
function cborEncode(val: unknown): Buffer {
  if (typeof val === 'number') {
    if (val >= 0) {
      if (val < 24) return Buffer.from([val]);
      if (val < 256) return Buffer.from([0x18, val]);
      const b = Buffer.alloc(3);
      b[0] = 0x19;
      b.writeUInt16BE(val, 1);
      return b;
    } else {
      const n = -1 - val;
      if (n < 24) return Buffer.from([0x20 | n]);
      return Buffer.from([0x38, n]);
    }
  }
  if (typeof val === 'string') {
    const strBuf = Buffer.from(val, 'utf8');
    const header =
      strBuf.length < 24
        ? Buffer.from([0x60 | strBuf.length])
        : Buffer.from([0x78, strBuf.length]);
    return Buffer.concat([header, strBuf]);
  }
  if (Buffer.isBuffer(val)) {
    const header =
      val.length < 24
        ? Buffer.from([0x40 | val.length])
        : val.length < 256
        ? Buffer.from([0x58, val.length])
        : Buffer.concat([Buffer.from([0x59]), (() => { const b = Buffer.alloc(2); b.writeUInt16BE(val.length, 0); return b; })()]);
    return Buffer.concat([header, val]);
  }
  if (val instanceof Map) {
    const entries: Buffer[] = [Buffer.from([0xa0 | val.size])];
    for (const [k, v] of val.entries()) {
      entries.push(cborEncode(k), cborEncode(v));
    }
    return Buffer.concat(entries);
  }
  throw new Error(`Unsupported CBOR type in test fixture: ${typeof val}`);
}

function createSoftwareAuthenticator(rpId: string, origin: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const credId = crypto.randomBytes(32);

  // COSE EC2 ES256 key map: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
  const coseMap = new Map<number, unknown>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, x],
    [-3, y],
  ]);
  const coseKeyBuf = cborEncode(coseMap);
  let signCount = 1;

  function buildAttestation(challenge: string, overrideRpId = rpId, overrideOrigin = origin) {
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge,
        origin: overrideOrigin,
        crossOrigin: false,
      }),
      'utf8'
    );

    const rpIdHash = crypto.createHash('sha256').update(overrideRpId).digest();
    const flags = Buffer.from([0x45]); // UP (0x01) + UV (0x04) + AT (0x40)
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(signCount, 0);
    const aaguid = Buffer.alloc(16, 0);
    const credLen = Buffer.alloc(2);
    credLen.writeUInt16BE(credId.length, 0);

    const authData = Buffer.concat([rpIdHash, flags, counterBuf, aaguid, credLen, credId, coseKeyBuf]);
    const attObjMap = new Map<string, unknown>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]);
    const attestationObject = cborEncode(attObjMap);

    const idB64u = credId.toString('base64url');
    return {
      id: idB64u,
      rawId: idB64u,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        attestationObject: attestationObject.toString('base64url'),
        transports: ['internal'],
      },
    };
  }

  function buildAssertion(
    challenge: string,
    opts?: { overrideRpId?: string; overrideOrigin?: string; forceCounter?: number }
  ) {
    const nextCounter = opts?.forceCounter ?? ++signCount;
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge,
        origin: opts?.overrideOrigin ?? origin,
        crossOrigin: false,
      }),
      'utf8'
    );

    const rpIdHash = crypto
      .createHash('sha256')
      .update(opts?.overrideRpId ?? rpId)
      .digest();
    const flags = Buffer.from([0x05]); // UP + UV
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(nextCounter, 0);
    const authenticatorData = Buffer.concat([rpIdHash, flags, counterBuf]);
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const sig = crypto.sign('sha256', Buffer.concat([authenticatorData, clientDataHash]), privateKey);

    const idB64u = credId.toString('base64url');
    return {
      id: idB64u,
      rawId: idB64u,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'),
        signature: sig.toString('base64url'),
      },
    };
  }

  return { buildAttestation, buildAssertion };
}

let baseUrl = '';
let port = 0;
let closeServer: (() => Promise<void>) | null = null;
let sessionToken = '';

describe('Standards-Compliant WebAuthn Passkey Verification Tests', () => {
  before(async () => {
    const srv = await startIsolatedServer(false);
    baseUrl = srv.baseUrl;
    port = srv.port;
    closeServer = srv.close;

    const reg = await apiFetch(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        fullName: 'Passkey Tester',
        email: 'passkey@example.org',
        password: 'StrongPassword#2026!',
        biometricConsent: true,
        selfieDataUrl: makeValidPngDataUrl(),
      },
    });
    assert.equal(reg.status, 201);
    sessionToken = reg.data.token as string;
  });

  after(async () => {
    if (closeServer) await closeServer();
    cleanupTestInstance();
  });

  it('completes real WebAuthn registration & assertion against active RP config and blocks origin/RP/replay/counter attacks', async () => {
    const activeAppUrl = process.env.APP_URL?.trim();
    if (activeAppUrl && activeAppUrl !== 'MY_APP_URL') {
      const parsedAppUrl = new URL(activeAppUrl);
      const rpAuth = createSoftwareAuthenticator(parsedAppUrl.hostname, parsedAppUrl.origin);
      const rpOpts = await apiFetch(baseUrl, '/api/auth/passkey/register/options', {
        method: 'POST',
        token: sessionToken,
        body: {},
      });
      assert.equal(rpOpts.status, 200);
      assert.equal(rpOpts.data.options.rp.id, parsedAppUrl.hostname);

      const rpAttest = rpAuth.buildAttestation(rpOpts.data.options.challenge);
      const rpVerify = await apiFetch(baseUrl, '/api/auth/passkey/register/verify', {
        method: 'POST',
        token: sessionToken,
        body: { label: 'Production RP Passkey', response: rpAttest },
      });
      assert.equal(rpVerify.status, 200);
      assert.equal(rpVerify.data.user.passkeyCount, 1);

      const rpAuthOpts = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/options', {
        method: 'POST',
        body: { email: 'passkey@example.org' },
      });
      assert.equal(rpAuthOpts.status, 200);
      assert.equal(rpAuthOpts.data.options.rpId, parsedAppUrl.hostname);
      const rpAssertVerify = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/verify', {
        method: 'POST',
        body: { response: rpAuth.buildAssertion(rpAuthOpts.data.options.challenge) },
      });
      assert.equal(rpAssertVerify.status, 200);
      assert.ok(rpAssertVerify.data.token);
    }

    // Now test dynamic local Relying Party resolution with APP_URL unset + negative security checks
    const prevAppUrl = process.env.APP_URL;
    const prevPubUrl = process.env.PUBLIC_BASE_URL;
    delete process.env.APP_URL;
    delete process.env.PUBLIC_BASE_URL;

    try {
      const expectedOrigin = `http://127.0.0.1:${port}`;
      const expectedRpId = '127.0.0.1';
      const authenticator = createSoftwareAuthenticator(expectedRpId, expectedOrigin);

      // 1. Registration options bound to actual local RP ID
      const regOpts = await apiFetch(baseUrl, '/api/auth/passkey/register/options', {
        method: 'POST',
        token: sessionToken,
        body: {},
      });
      assert.equal(regOpts.status, 200);
      assert.equal(regOpts.data.options.rp.id, expectedRpId);
      const regChallenge = regOpts.data.options.challenge as string;

      // 2. Reject wrong origin during registration
      const badOriginAttest = authenticator.buildAttestation(
        regChallenge,
        expectedRpId,
        'https://phishing.attacker.example'
      );
      const badOriginReg = await apiFetch(baseUrl, '/api/auth/passkey/register/verify', {
        method: 'POST',
        token: sessionToken,
        body: { label: 'Bad Origin Key', response: badOriginAttest },
      });
      assert.equal(badOriginReg.status, 400);

    // 3. Re-issue fresh registration challenge and register legitimately
    const regOpts2 = await apiFetch(baseUrl, '/api/auth/passkey/register/options', {
      method: 'POST',
      token: sessionToken,
      body: {},
    });
    assert.equal(regOpts2.status, 200);
    const regChallenge2 = regOpts2.data.options.challenge as string;

    const validAttest = authenticator.buildAttestation(regChallenge2);
    const regVerify = await apiFetch(baseUrl, '/api/auth/passkey/register/verify', {
      method: 'POST',
      token: sessionToken,
      body: { label: 'Hardware Test Key', response: validAttest },
    });
    assert.equal(regVerify.status, 200);
    assert.equal(regVerify.data.ok, true);
    assert.equal(regVerify.data.user.passkeyCount, activeAppUrl && activeAppUrl !== 'MY_APP_URL' ? 2 : 1);

    // 4. Legitimate WebAuthn authentication ceremony
    const authOpts = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/options', {
      method: 'POST',
      body: { email: 'passkey@example.org' },
    });
    assert.equal(authOpts.status, 200);
    assert.equal(authOpts.data.options.rpId, expectedRpId);
    const authChallenge = authOpts.data.options.challenge as string;

    const validAssertion = authenticator.buildAssertion(authChallenge); // counter = 2
    const authVerify = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: { response: validAssertion },
    });
    assert.equal(authVerify.status, 200);
    assert.ok(authVerify.data.token);
    assert.equal(authVerify.data.user.email, 'passkey@example.org');

    // 5. Challenge replay must be rejected
    const replayRes = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: { response: validAssertion },
    });
    assert.equal(replayRes.status, 400);

    // 6. Wrong origin on assertion must fail
    const optsWrongOrigin = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/options', {
      method: 'POST',
      body: { email: 'passkey@example.org' },
    });
    const wrongOriginAssert = authenticator.buildAssertion(optsWrongOrigin.data.options.challenge, {
      overrideOrigin: 'https://evil.example.com',
    });
    const wrongOriginRes = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: { response: wrongOriginAssert },
    });
    assert.equal(wrongOriginRes.status, 401);

    // 7. Wrong RP ID hash on assertion must fail
    const optsWrongRp = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/options', {
      method: 'POST',
      body: { email: 'passkey@example.org' },
    });
    const wrongRpAssert = authenticator.buildAssertion(optsWrongRp.data.options.challenge, {
      overrideRpId: 'evil.example.com',
    });
    const wrongRpRes = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: { response: wrongRpAssert },
    });
    assert.equal(wrongRpRes.status, 401);

    // 8. Signature counter rollback (cloned authenticator detection) must fail
    const optsRollback = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/options', {
      method: 'POST',
      body: { email: 'passkey@example.org' },
    });
    const rollbackAssert = authenticator.buildAssertion(optsRollback.data.options.challenge, {
      forceCounter: 1, // stored counter is already 2
    });
    const rollbackRes = await apiFetch(baseUrl, '/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: { response: rollbackAssert },
    });
    assert.equal(rollbackRes.status, 401);
    assert.ok(String(rollbackRes.data.error).toLowerCase().includes('counter'));
    } finally {
      if (prevAppUrl !== undefined) process.env.APP_URL = prevAppUrl;
      if (prevPubUrl !== undefined) process.env.PUBLIC_BASE_URL = prevPubUrl;
    }
  });
});
