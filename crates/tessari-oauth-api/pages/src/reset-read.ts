// What the password-reset pages decide, kept apart from the document so it can be tested without a browser: where
// the API is for the reset page, the token a reset link carries, and where each answer leaves the user. A request
// for a link answers alike for every address, so nothing here can tell whether an account exists.

import { type ChangeRefusal, changeRefusal } from "./account-read.ts";
import { type Refusal, field, refusal } from "./flow.ts";

/** Where a reset request leaves the user. */
export type RequestOutcome = { kind: "sent" } | { kind: "unavailable" } | Refusal;

/** Where a new password leaves the user. */
export type CompleteOutcome =
  | { kind: "changed" }
  | { kind: "link" }
  | { kind: "password"; why: ChangeRefusal }
  | Refusal;

/** A reset link's fragment: one token of 256 bits in unpadded base64url, and nothing else. */
const FRAGMENT = /^#token=([A-Za-z0-9_-]{43})$/;

/** The sign-in API for the reset page at `pathname`, which is `<tenant path>/login/reset`. */
export function resetApi(pathname: string): string | null {
  const suffix = "/login/reset";
  if (!pathname.endsWith(suffix)) {
    return null;
  }
  const tenant = pathname.slice(0, -suffix.length);
  return tenant.length > 1 ? `${tenant}/login/api` : null;
}

/** The token in a reset link's fragment `hash`, or null when the fragment is not exactly one token. */
export function readResetToken(hash: string): string | null {
  return FRAGMENT.exec(hash)?.[1] ?? null;
}

/** Where the answer to a reset request leaves the user, from its `status`, its body and its `Retry-After`. */
export function requestOutcome(status: number, body: unknown, retryAfter: string | null): RequestOutcome {
  if (status === 202) {
    return { kind: "sent" };
  }
  if (status === 503 && field(body, "code") === "mail_unavailable") {
    return { kind: "unavailable" };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}

/** Where the answer to a new password leaves the user, from its `status`, its body and its `Retry-After`. */
export function completeOutcome(status: number, body: unknown, retryAfter: string | null): CompleteOutcome {
  if (status === 204) {
    return { kind: "changed" };
  }
  const code = field(body, "code");
  if (status === 400 && code === "code_rejected") {
    return { kind: "link" };
  }
  if (status === 400 && code === "password_rejected") {
    return { kind: "password", why: changeRefusal(status, body) };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}
