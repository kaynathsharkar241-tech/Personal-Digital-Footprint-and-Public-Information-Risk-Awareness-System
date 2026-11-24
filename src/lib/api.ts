import {
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

// In-memory session and reviewer tokens (never persisted in localStorage or sessionStorage)
let sessionToken: string | null = null;
let reviewerToken: string | null = null;

export function setSessionToken(token: string | null) {
  sessionToken = token;
}

export function getSessionToken(): string | null {
  return sessionToken;
}

export function setReviewerToken(token: string | null) {
  reviewerToken = token;
}

export function getReviewerToken(): string | null {
  return reviewerToken;
}

export async function apiRequest<T>(
  url: string,
  options: RequestInit = {},
  extraHeaders: Record<string, string> = {}
): Promise<T> {
  const headers: Record<string, string> = {
    ...extraHeaders,
  };
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  if (sessionToken) {
    headers.Authorization = `Bearer ${sessionToken}`;
  }
  if (reviewerToken && url.startsWith('/api/reviewer')) {
    headers['X-Reviewer-Token'] = reviewerToken;
  }

  const res = await fetch(url, { ...options, headers });
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Request failed with status ${res.status}`);
    }
    return data as T;
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed with status ${res.status}`);
  }
  return (await res.blob()) as unknown as T;
}

export async function fetchProtectedBlobUrl(
  url: string,
  useReviewerToken = false
): Promise<string> {
  const headers: Record<string, string> = {};
  if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
  if (useReviewerToken && reviewerToken) headers['X-Reviewer-Token'] = reviewerToken;

  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`Failed to fetch protected resource (${res.status})`);
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

export function fileToDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error('Could not read selected file.'));
    reader.readAsDataURL(file);
  });
}

export async function registerBrowserPasskey(_email: string, _name: string, label: string) {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('WebAuthn passkeys are not supported in this browser context.');
  }
  const { options } = await apiRequest<{ options: PublicKeyCredentialCreationOptionsJSON }>(
    '/api/auth/passkey/register/options',
    {
      method: 'POST',
      body: JSON.stringify({}),
    }
  );

  const response = await startRegistration({ optionsJSON: options });

  return apiRequest<{ ok: boolean; user: unknown }>('/api/auth/passkey/register/verify', {
    method: 'POST',
    body: JSON.stringify({
      challenge: options.challenge,
      label,
      response,
    }),
  });
}

export async function authenticateWithPasskey(email: string) {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('WebAuthn passkeys are not supported in this browser context.');
  }
  const { options } = await apiRequest<{ options: PublicKeyCredentialRequestOptionsJSON }>(
    '/api/auth/passkey/authenticate/options',
    {
      method: 'POST',
      body: JSON.stringify({ email }),
    }
  );

  const response = await startAuthentication({ optionsJSON: options });

  return apiRequest<{ token: string; user: unknown }>('/api/auth/passkey/authenticate/verify', {
    method: 'POST',
    body: JSON.stringify({
      challenge: options.challenge,
      response,
    }),
  });
}
