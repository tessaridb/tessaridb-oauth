// What the address-change pages decide, kept apart from the document so it can be tested without a browser: where the
// API is for the page the change mails open, which link the fragment carries, and where each answer leaves the user
// there and on the account page. Every link that does not work gets one answer, so nothing here says why.

import { type Refusal, field, refusal } from "./flow.ts";

/** The link a change mail carries: the new address's confirmation or the old address's cancellation. */
export type EmailLink = { kind: "confirm" | "cancel"; token: string };

/** Where opening a confirmation link leaves the user. */
export type ConfirmOutcome = { kind: "confirmed"; effectiveAt: number } | { kind: "link" } | Refusal;

/** Where cancelling a change leaves the user. */
export type CancelOutcome = { kind: "cancelled" } | { kind: "link" } | Refusal;

/** Where asking for a change from the account page leaves the user. */
export type AskOutcome =
  | { kind: "sent" }
  | { kind: "same" }
  | { kind: "invalid" }
  | { kind: "reauthenticate" }
  | { kind: "signed-out" }
  | { kind: "unavailable" }
  | Refusal;

/** A change link's fragment: one token of 256 bits in unpadded base64url, named for what it does, and nothing else. */
const FRAGMENT = /^#(confirm|cancel)=([A-Za-z0-9_-]{43})$/;

/** The sign-in API for the address-change page at `pathname`, which is `<tenant path>/login/email`. */
export function emailApi(pathname: string): string | null {
  const suffix = "/login/email";
  if (!pathname.endsWith(suffix)) {
    return null;
  }
  const tenant = pathname.slice(0, -suffix.length);
  return tenant.length > 1 ? `${tenant}/login/api` : null;
}

/** The link in a change mail's fragment `hash`, or null when the fragment is not exactly one. */
export function readEmailLink(hash: string): EmailLink | null {
  const match = FRAGMENT.exec(hash);
  const [, kind, token] = match ?? [];
  if ((kind !== "confirm" && kind !== "cancel") || token === undefined) {
    return null;
  }
  return { kind, token };
}

/** Where the answer to an opened confirmation link leaves the user, from its `status`, body and `Retry-After`. */
export function confirmOutcome(status: number, body: unknown, retryAfter: string | null): ConfirmOutcome {
  const effectiveAt = field(body, "effective_at");
  if (status === 202) {
    return typeof effectiveAt === "number" ? { kind: "confirmed", effectiveAt } : { kind: "retry" };
  }
  return spent(status, body, retryAfter);
}

/** Where the answer to a cancellation leaves the user, from its `status`, body and `Retry-After`. */
export function cancelOutcome(status: number, body: unknown, retryAfter: string | null): CancelOutcome {
  return status === 204 ? { kind: "cancelled" } : spent(status, body, retryAfter);
}

/** Where the answer to a requested change leaves the user, from its `status`, body and `Retry-After`. */
export function askOutcome(status: number, body: unknown, retryAfter: string | null): AskOutcome {
  if (status === 202) {
    return { kind: "sent" };
  }
  if (status === 204) {
    return { kind: "same" };
  }
  const code = field(body, "code");
  if (status === 400 && code === "email_rejected") {
    return { kind: "invalid" };
  }
  if (status === 401 && code === "reauthentication_required") {
    return { kind: "reauthenticate" };
  }
  if (status === 401 && code === "session_required") {
    return { kind: "signed-out" };
  }
  if (status === 503 && code === "mail_unavailable") {
    return { kind: "unavailable" };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}

/** A link that did not work, a wait, or anything else to try again. */
function spent(status: number, body: unknown, retryAfter: string | null): { kind: "link" } | Refusal {
  if (status === 400 && field(body, "code") === "code_rejected") {
    return { kind: "link" };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}
