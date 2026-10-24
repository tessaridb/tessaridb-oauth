// What the audit trail view decides, kept apart from the document: a page of the company's trail in the order the
// server keeps it, each message with only the fields it was written with, named for a reader, in one fixed order.
// A field of the wrong shape makes the page unreadable rather than shown in part.

import { field } from "./flow.ts";

/** One message of the trail: its position, when, what kind, and its present fields as label and value. */
export interface AuditEvent {
  position: number;
  at: number;
  kind: string;
  details: [string, string][];
}

/** A page of the trail and the position to read after next, when the page was full. */
export interface AuditPage {
  events: AuditEvent[];
  next: number | null;
}

/** How a field is read: text as it is, scopes joined by spaces, a count as a number. */
type Shape = "text" | "scopes" | "count";

/** The fields a message may carry, in the order they are shown, with the label and shape of each. */
const FIELDS: readonly [string, string, Shape][] = [
  ["client_id", "Client", "text"],
  ["scopes", "Scopes", "scopes"],
  ["user", "Account", "text"],
  ["families", "Refresh families", "count"],
  ["subject", "Subject", "text"],
  ["audience", "Audience", "text"],
  ["jti", "Token id", "text"],
  ["auth_method", "Client authentication", "text"],
  ["bound_to", "Bound to key", "text"],
  ["reason", "Reason", "text"],
  ["actor", "Operator", "text"],
  ["role", "Role", "text"],
  ["action", "Action", "text"],
];

/** The address of the trail page after the position `after`. */
export function auditPath(after: number | null): string {
  return after === null ? "api/audit" : `api/audit?after=${after}`;
}

function natural(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function readEvent(value: unknown): AuditEvent | null {
  const position = natural(field(value, "position"));
  const at = natural(field(value, "at"));
  const kind = field(value, "kind");
  if (position === null || at === null || typeof kind !== "string") {
    return null;
  }
  const details: [string, string][] = [];
  for (const [key, label, shape] of FIELDS) {
    const raw = field(value, key);
    if (raw === undefined) {
      continue;
    }
    const text = shown(raw, shape);
    if (text === null) {
      return null;
    }
    details.push([label, text]);
  }
  return { position, at, kind, details };
}

/** `raw` as text for a field of `shape`, or null when it is not that shape. */
function shown(raw: unknown, shape: Shape): string | null {
  switch (shape) {
    case "text":
      return typeof raw === "string" ? raw : null;
    case "scopes":
      return Array.isArray(raw) && raw.every((scope) => typeof scope === "string") ? raw.join(" ") : null;
    case "count": {
      const count = natural(raw);
      return count === null ? null : String(count);
    }
  }
}

/** `GET api/audit`'s answer, or null when any part of it is not the shape the console knows. */
export function readAuditPage(body: unknown): AuditPage | null {
  const listed = field(body, "events");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== null && natural(next) === null)) {
    return null;
  }
  const events: AuditEvent[] = [];
  for (const value of listed) {
    const event = readEvent(value);
    if (event === null) {
      return null;
    }
    events.push(event);
  }
  return { events, next: next === null ? null : natural(next) };
}
