// What the sign-in page decides about opening an account, kept apart from the document so it can be tested without a
// browser: whether the company lets people open their own, and where each answer to a request leaves the user. An
// accepted request answers alike for every address, so nothing here can tell whether an account exists.

import { type Refusal, field, refusal } from "./flow.ts";

/** Where a request to open an account leaves the user. */
export type RegisterOutcome =
  | { kind: "sent" }
  | { kind: "unavailable" }
  | { kind: "domain" }
  | { kind: "address" }
  | { kind: "closed" }
  | Refusal;

/** Whether `GET .../registration` said the company lets people open their own account; anything else is closed. */
export function readOpen(body: unknown): boolean {
  return field(body, "open") === true;
}

/** Where the answer to a request to open an account leaves the user, from its `status`, body and `Retry-After`. */
export function registerOutcome(status: number, body: unknown, retryAfter: string | null): RegisterOutcome {
  const code = field(body, "code");
  if (status === 202) {
    return { kind: "sent" };
  }
  if (status === 503 && code === "mail_unavailable") {
    return { kind: "unavailable" };
  }
  if (status === 400 && code === "address_not_accepted") {
    return { kind: "domain" };
  }
  if (status === 400 && code === "email_rejected") {
    return { kind: "address" };
  }
  if (status === 404) {
    return { kind: "closed" };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}
