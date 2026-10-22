// What the operators view decides, kept apart from the document: the grants page as the server answers it, a
// revocation made, and the validity the grant form asks for. A grant of a role the console does not know makes the
// whole page unreadable rather than shown under a guessed name.

import { type Role, isRole } from "./console-read.ts";
import { field } from "./flow.ts";

/** The days a grant lasts when the form leaves the field empty, and the most it may ask for, as the server has it. */
const DEFAULT_DAYS = 90;
const MAX_DAYS = 365;

/** One operator grant: who holds which role, who granted it and why, and until when. */
export interface Grant {
  user: string;
  role: Role;
  grantedBy: string;
  grantedAt: number;
  expiresAt: number | null;
  reason: string;
}

/** A page of grants and the cursor of the next one, when there is one. */
export interface GrantsPage {
  grants: Grant[];
  next: string | null;
}

/** The address of the grants page after the cursor `after`. */
export function operatorsPath(after: string | null): string {
  return after === null ? "api/operators" : `api/operators?${new URLSearchParams({ after }).toString()}`;
}

function seconds(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function readGrant(value: unknown): Grant | null {
  const user = field(value, "user");
  const role = field(value, "role");
  const grantedBy = field(value, "granted_by");
  const grantedAt = seconds(field(value, "granted_at"));
  const expires = field(value, "expires_at");
  const expiresAt = expires === null ? null : seconds(expires);
  const reason = field(value, "reason");
  if (
    typeof user !== "string" || user === "" || typeof role !== "string" || !isRole(role)
    || typeof grantedBy !== "string" || grantedAt === null || (expires !== null && expiresAt === null)
    || typeof reason !== "string"
  ) {
    return null;
  }
  return { user, role, grantedBy, grantedAt, expiresAt, reason };
}

/** `GET api/operators`'s answer, or null when any part of it is not the shape the console knows. */
export function readGrantsPage(body: unknown): GrantsPage | null {
  const listed = field(body, "operators");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== null && typeof next !== "string")) {
    return null;
  }
  const grants: Grant[] = [];
  for (const value of listed) {
    const grant = readGrant(value);
    if (grant === null) {
      return null;
    }
    grants.push(grant);
  }
  return { grants, next };
}

/** A revocation the server says it made. */
export function readRevoked(body: unknown): { user: string; role: string } | null {
  const user = field(body, "user");
  const role = field(body, "role");
  return field(body, "revoked") === true && typeof user === "string" && typeof role === "string"
    ? { user, role }
    : null;
}

/** The whole days `typed` asks a grant to last (1 to 365, empty for the default), or null. */
export function daysOf(typed: string): number | null {
  const text = typed.trim();
  if (text === "") {
    return DEFAULT_DAYS;
  }
  if (!/^\d{1,3}$/.test(text)) {
    return null;
  }
  const days = Number(text);
  return days >= 1 && days <= MAX_DAYS ? days : null;
}
