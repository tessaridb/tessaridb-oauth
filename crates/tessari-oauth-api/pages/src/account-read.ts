// What the account page reads from the account API, kept apart from the document so it can be tested without a
// browser. Every answer is read as unknown and narrowed; a field of another shape makes the whole answer null, so
// the page says it could not load rather than showing something half-read.

import { field, strings } from "./flow.ts";

/** A passkey the user holds. */
export interface HeldPasskey {
  id: string;
  createdAt: number;
  synced: boolean;
}

/** The signed-in user's account and how it signs in. */
export interface Me {
  email: string;
  emailVerified: boolean;
  password: boolean;
  totp: boolean;
  recoveryCodes: number;
  passkeys: HeldPasskey[];
}

/** One of the user's sessions at this issuer. */
export interface ListedSession {
  sid: string;
  signedInAt: number;
  lastSeenAt: number;
  methods: string[];
  current: boolean;
}

/** One application the user has granted access to. */
export interface ListedGrant {
  clientId: string;
  scopes: string[];
  resources: string[];
  grantedAt: number;
}

/** The account API for a page at `pathname`, which is `<tenant path>/account`; null when the page is not there. */
export function accountApi(pathname: string): string | null {
  const suffix = "/account";
  if (!pathname.endsWith(suffix)) {
    return null;
  }
  const tenant = pathname.slice(0, -suffix.length);
  return tenant.length > 1 ? `${tenant}/account/api` : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function flag(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** A whole, non-negative number: a count or a Unix time in seconds. */
function count(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** Every item of `value` read by `read`, or null when `value` is not a list or any item does not read. */
function every<T>(value: unknown, read: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const items: T[] = [];
  for (const item of value) {
    const readItem = read(item);
    if (readItem === null) {
      return null;
    }
    items.push(readItem);
  }
  return items;
}

function readPasskey(value: unknown): HeldPasskey | null {
  const id = text(field(value, "id"));
  const createdAt = count(field(value, "created_at"));
  const synced = flag(field(value, "synced"));
  return id === null || createdAt === null || synced === null ? null : { id, createdAt, synced };
}

/** `GET account/api/me`. */
export function readMe(answer: unknown): Me | null {
  const factors = field(answer, "factors");
  const email = text(field(answer, "email"));
  const emailVerified = flag(field(answer, "email_verified"));
  const password = flag(field(factors, "password"));
  const totp = flag(field(factors, "totp"));
  const recoveryCodes = count(field(factors, "recovery_codes"));
  const passkeys = every(field(factors, "passkeys"), readPasskey);
  if (
    email === null ||
    emailVerified === null ||
    password === null ||
    totp === null ||
    recoveryCodes === null ||
    passkeys === null
  ) {
    return null;
  }
  return { email, emailVerified, password, totp, recoveryCodes, passkeys };
}

function readSession(value: unknown): ListedSession | null {
  const sid = text(field(value, "sid"));
  const signedInAt = count(field(value, "signed_in_at"));
  const lastSeenAt = count(field(value, "last_seen_at"));
  const methods = strings(field(value, "methods"));
  const current = flag(field(value, "current"));
  if (sid === null || signedInAt === null || lastSeenAt === null || methods === null || current === null) {
    return null;
  }
  return { sid, signedInAt, lastSeenAt, methods, current };
}

/** `GET account/api/sessions`. */
export function readSessions(answer: unknown): ListedSession[] | null {
  return every(field(answer, "sessions"), readSession);
}

function readGrant(value: unknown): ListedGrant | null {
  const clientId = text(field(value, "client_id"));
  const scopes = strings(field(value, "scopes"));
  const resources = strings(field(value, "resources"));
  const grantedAt = count(field(value, "granted_at"));
  if (clientId === null || scopes === null || resources === null || grantedAt === null) {
    return null;
  }
  return { clientId, scopes, resources, grantedAt };
}

/** `GET account/api/grants`. */
export function readGrants(answer: unknown): ListedGrant[] | null {
  return every(field(answer, "grants"), readGrant);
}

/** When the access tokens already issued stop working, from an answer that ended something. */
export function readEndBy(answer: unknown): number | null {
  return count(field(answer, "access_tokens_end_by"));
}
