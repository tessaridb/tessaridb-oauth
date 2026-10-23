// What the Mail view reads and sends, kept apart from the document: every kind of mail as `GET api/mail` answers it,
// with the revision a change must name, the bodies of a change and a reset, and the server's own words for a rule
// the wording broke.

import { field, strings } from "./flow.ts";

/** One kind of mail: the wording the company sends it with, and the placeholders it may and must carry. */
export interface Mail {
  kind: string;
  subject: string;
  text: string;
  /** Whether the wording is the company's own rather than the default. */
  own: boolean;
  /** The revision a change names; 0 when the company keeps no wording of its own. */
  revision: number;
  placeholders: string[];
  required: string[];
}

const TITLES: readonly [string, string][] = [
  ["reset", "Password reset"],
  ["verify", "Address verification"],
  ["email_confirm", "New address: confirm"],
  ["email_taken", "New address: already in use"],
  ["email_cancel", "Address change: cancel link"],
  ["email_applied_old", "Address changed: to the old address"],
  ["email_applied_new", "Address changed: to the new address"],
  ["email_refused", "Address change refused"],
  ["signin_changed", "Sign-in change notice"],
  ["enrolment", "Enrolment link"],
];

function one(row: unknown): Mail | null {
  const kind = field(row, "kind");
  const subject = field(row, "subject");
  const text = field(row, "text");
  const own = field(row, "own");
  const revision = field(row, "revision");
  const placeholders = strings(field(row, "placeholders"));
  const required = strings(field(row, "required"));
  if (
    typeof kind !== "string" ||
    typeof subject !== "string" ||
    typeof text !== "string" ||
    typeof own !== "boolean" ||
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    placeholders === null ||
    required === null
  ) {
    return null;
  }
  return { kind, subject, text, own, revision, placeholders, required };
}

/** `GET api/mail`'s answer, or null for any other shape. */
export function readMail(body: unknown): Mail[] | null {
  const rows = field(body, "mail");
  if (!Array.isArray(rows)) {
    return null;
  }
  const read = rows.map(one);
  return read.every((row): row is Mail => row !== null) ? read : null;
}

/** The body of a change to a kind's wording at `revision`. */
export function mailBody(revision: number, subject: string, text: string, reason: string): Record<string, unknown> {
  return { revision, subject, text, reason };
}

/** The body of a reset of the company's own wording at `revision`. */
export function resetBody(revision: number, reason: string): Record<string, unknown> {
  return { revision, reason };
}

/** The server's words for the rule a refused wording broke, or null when the refusal is not about the wording. */
export function ruleMessage(body: unknown): string | null {
  const message = field(body, "message");
  return field(body, "code") === "template_rejected" && typeof message === "string" ? message : null;
}

/** The title of the kind `kind`, or its name when the console does not know it. */
export function mailTitle(kind: string): string {
  return TITLES.find(([name]) => name === kind)?.[1] ?? kind;
}
