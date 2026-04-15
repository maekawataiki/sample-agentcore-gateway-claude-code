/** Cognito Hosted UI auth with PKCE. */

declare global {
  interface Window {
    __CONFIG__: {
      cognitoDomain: string;
      cognitoClientId: string;
      adminApiUrl: string;
      redirectUri: string;
    };
  }
}

export function getConfig() {
  return window.__CONFIG__;
}

// ── PKCE helpers ──

function generateRandomString(len: number): string {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, len);
}

async function sha256(str: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
}

function base64UrlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ── Auth flow ──

export async function login(): Promise<void> {
  const cfg = getConfig();
  const codeVerifier = generateRandomString(64);
  const codeChallenge = base64UrlEncode(await sha256(codeVerifier));
  sessionStorage.setItem("pkce_code_verifier", codeVerifier);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.cognitoClientId,
    redirect_uri: cfg.redirectUri,
    scope: "openid email profile",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  window.location.href = `${cfg.cognitoDomain}/oauth2/authorize?${params}`;
}

export async function handleCallback(code: string): Promise<boolean> {
  const cfg = getConfig();
  const codeVerifier = sessionStorage.getItem("pkce_code_verifier");
  if (!codeVerifier) return false;

  const resp = await fetch(`${cfg.cognitoDomain}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: cfg.cognitoClientId,
      redirect_uri: cfg.redirectUri,
      code,
      code_verifier: codeVerifier,
    }),
  });

  if (!resp.ok) return false;
  const tokens = await resp.json();
  sessionStorage.setItem("id_token", tokens.id_token);
  sessionStorage.setItem("access_token", tokens.access_token);
  sessionStorage.removeItem("pkce_code_verifier");
  return true;
}

export function getToken(): string | null {
  return sessionStorage.getItem("id_token");
}

export function isLoggedIn(): boolean {
  return !!getToken();
}

export function logout(): void {
  const cfg = getConfig();
  sessionStorage.clear();
  window.location.href = `${cfg.cognitoDomain}/logout?client_id=${cfg.cognitoClientId}&logout_uri=${encodeURIComponent(cfg.redirectUri)}`;
}

export function getUserInfo(): {
  username: string;
  email: string;
  groups: string[];
} | null {
  const token = getToken();
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    return {
      username: payload["cognito:username"] || payload.sub,
      email: payload.email || "",
      groups: payload["cognito:groups"] || [],
    };
  } catch {
    return null;
  }
}
