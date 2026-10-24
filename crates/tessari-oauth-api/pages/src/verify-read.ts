// What the address-verification pages decide, kept apart from the document so it can be tested without a browser:
// where the API is for the page a verification link opens, the token the link carries, and where each answer leaves
// the user there and on the account page. Every token that does not verify gets one answer.

import { field, type Refusal, refusal } from "./flow.ts";
import { readResetToken } from "./reset-read.ts";

/** Where opening a verification link leaves the user. */
export type VerifyOutcome = { kind: "verified" } | { kind: "link" } | Refusal;

/** Where asking for a verification link leaves the user. */
export type SendOutcome =
  | { kind: "sent" }
  | { kind: "verified" }
  | { kind: "unavailable" }
  | { kind: "signed-out" }
  | Refusal;

/** The sign-in API for the verification page at `pathname`, which is `<tenant path>/login/verify`. */
export function verifyApi(pathname: string): string | null {
  const suffix = "/login/verify";
  if (!pathname.endsWith(suffix)) {
    return null;
  }
  const tenant = pathname.slice(0, -suffix.length);
  return tenant.length > 1 ? `${tenant}/login/api` : null;
}

/** The token in a verification link's fragment `hash`; a verification link carries it as a reset link does. */
export function readVerifyToken(hash: string): string | null {
  return readResetToken(hash);
}

/** Where the answer to an opened link leaves the user, from its `status`, its body and its `Retry-After`. */
export function verifyOutcome(status: number, body: unknown, retryAfter: string | null): VerifyOutcome {
  if (status === 204) {
    return { kind: "verified" };
  }
  if (status === 400 && field(body, "code") === "code_rejected") {
    return { kind: "link" };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}

/** Where the answer to a request for a link leaves the user, from its `status`, its body and its `Retry-After`. */
export function sendOutcome(status: number, body: unknown, retryAfter: string | null): SendOutcome {
  if (status === 202) {
    return { kind: "sent" };
  }
  if (status === 204) {
    return { kind: "verified" };
  }
  const code = field(body, "code");
  if (status === 503 && code === "mail_unavailable") {
    return { kind: "unavailable" };
  }
  if (status === 401 && code === "session_required") {
    return { kind: "signed-out" };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}
