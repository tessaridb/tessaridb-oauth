// What the pages decide, kept apart from the document so it can be tested without a browser: where the API is,
// what an answer from it means, and the base64url the passkey step speaks. Every answer is read as unknown and
// narrowed here; nothing the server sends is trusted for its shape.

/** The steps a sign-in moves through, as the server names them. */
export type Step = "identify" | "first_factor" | "second_factor" | "complete";

const STEPS: readonly Step[] = ["identify", "first_factor", "second_factor", "complete"];

/** Where a refusal leaves the user. */
export type Refusal =
  | { kind: "rejected" }
  | { kind: "expired" }
  | { kind: "throttled"; seconds: number | null }
  | { kind: "retry" };

/** What the consent page is asked to show. */
export interface Delta {
  clientId: string;
  scopes: string[];
  resources: string[];
}

/** The field `key` of `value`, when `value` is an object that has one. */
function field(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const fields: [string, unknown][] = Object.entries(value);
  return fields.find(([name]) => name === key)?.[1];
}

function strings(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : null;
}

function url(text: unknown): URL | null {
  if (typeof text !== "string") {
    return null;
  }
  try {
    return new URL(text);
  } catch {
    return null;
  }
}

/** The sign-in API for a page at `pathname`, which is `<tenant path>/<page>`; null when the page is not there. */
export function apiBase(pathname: string, page: "login" | "consent"): string | null {
  const suffix = `/${page}`;
  if (!pathname.endsWith(suffix)) {
    return null;
  }
  const tenant = pathname.slice(0, -suffix.length);
  return tenant.length > 1 ? `${tenant}/login/api` : null;
}

/** The step a step's answer names. */
export function readNext(answer: unknown): Step | null {
  const next = field(answer, "next");
  return STEPS.find((step) => step === next) ?? null;
}

/** Where a completed sign-in continues, when that is on this server's `origin`. */
export function readCompleted(answer: unknown, origin: string): string | null {
  if (readNext(answer) !== "complete") {
    return null;
  }
  const target = url(field(answer, "continue"));
  return target !== null && target.origin === origin ? target.href : null;
}

/** Where a consent decision sends the browser: the application's address, never a script or a document. */
export function readRedirect(answer: unknown): string | null {
  const target = url(field(answer, "redirect"));
  if (target === null || ["javascript:", "data:", "vbscript:", "blob:", "file:"].includes(target.protocol)) {
    return null;
  }
  return target.href;
}

/** What the consent page is told is asked and not yet granted. */
export function readDelta(answer: unknown): Delta | null {
  const clientId = field(answer, "client_id");
  const scopes = strings(field(answer, "scopes"));
  const resources = strings(field(answer, "resources"));
  if (typeof clientId !== "string" || scopes === null || resources === null) {
    return null;
  }
  return { clientId, scopes, resources };
}

/** Where a refused step leaves the user, from its `status`, its body and its `Retry-After` header. */
export function refusal(status: number, body: unknown, retryAfter: string | null): Refusal {
  const code = field(body, "code");
  if (status === 401 && code === "credentials_rejected") {
    return { kind: "rejected" };
  }
  if (status === 410 || code === "session_required") {
    return { kind: "expired" };
  }
  if (status === 429) {
    const seconds = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
    return { kind: "throttled", seconds };
  }
  return { kind: "retry" };
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** `bytes` in unpadded base64url (RFC 4648 §5). */
export function toBase64url(bytes: Uint8Array): string {
  let text = "";
  for (let at = 0; at < bytes.length; at += 3) {
    const chunk = bytes.subarray(at, at + 3);
    const bits = ((chunk[0] ?? 0) << 16) | ((chunk[1] ?? 0) << 8) | (chunk[2] ?? 0);
    const sextets = [bits >> 18, bits >> 12, bits >> 6, bits].map((value) => ALPHABET[value & 63] ?? "");
    text += sextets.slice(0, chunk.length + 1).join("");
  }
  return text;
}

/** The bytes unpadded base64url `text` carries, or null when it is not base64url. */
export function fromBase64url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    return null;
  }
  const bytes: number[] = [];
  let bits = 0;
  let held = 0;
  for (const char of text) {
    bits = (bits << 6) | ALPHABET.indexOf(char);
    held += 6;
    if (held >= 8) {
      held -= 8;
      bytes.push((bits >> held) & 255);
    }
  }
  return Uint8Array.from(bytes);
}

/** What the browser is asked for when a passkey signs in. */
export interface PasskeyOptions {
  challenge: Uint8Array<ArrayBuffer>;
  rpId: string;
  userVerification: "required" | "preferred";
  timeout: number;
}

/** The passkey options the server answered, decoded for the browser. */
export function readPasskeyOptions(answer: unknown): PasskeyOptions | null {
  const challenge = field(answer, "challenge");
  const rpId = field(answer, "rp_id");
  const verification = field(answer, "user_verification");
  const timeout = field(answer, "timeout_ms");
  const bytes = typeof challenge === "string" ? fromBase64url(challenge) : null;
  if (bytes === null || bytes.length === 0 || typeof rpId !== "string" || typeof timeout !== "number") {
    return null;
  }
  if (verification !== "required" && verification !== "preferred") {
    return null;
  }
  return { challenge: bytes, rpId, userVerification: verification, timeout };
}
