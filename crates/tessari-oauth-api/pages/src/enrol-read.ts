// What the enrolment page decides, kept apart from the document so it can be tested without a browser: where the API
// is for the page, the code an enrolment link carries, and where each answer to a first password leaves the user.

import { type ChangeRefusal, changeRefusal } from "./account-read.ts";
import { type Refusal, field, refusal } from "./flow.ts";

/** Where a first password leaves the user. */
export type EnrolOutcome =
  | { kind: "set" }
  | { kind: "link" }
  | { kind: "already" }
  | { kind: "password"; why: ChangeRefusal }
  | Refusal;

/** An enrolment link's fragment: one code of 256 bits in unpadded base64url, and nothing else. */
const FRAGMENT = /^#code=([A-Za-z0-9_-]{43})$/;

/** The sign-in API for the enrolment page at `pathname`, which is `<tenant path>/login/enrol`. */
export function enrolApi(pathname: string): string | null {
  const suffix = "/login/enrol";
  if (!pathname.endsWith(suffix)) {
    return null;
  }
  const tenant = pathname.slice(0, -suffix.length);
  return tenant.length > 1 ? `${tenant}/login/api` : null;
}

/** The code in an enrolment link's fragment `hash`, or null when the fragment is not exactly one code. */
export function readEnrolCode(hash: string): string | null {
  return FRAGMENT.exec(hash)?.[1] ?? null;
}

/** Where the answer to a first password leaves the user, from its `status`, its body and its `Retry-After`. */
export function enrolOutcome(status: number, body: unknown, retryAfter: string | null): EnrolOutcome {
  if (status === 204) {
    return { kind: "set" };
  }
  const code = field(body, "code");
  if (status === 400 && code === "code_rejected") {
    return { kind: "link" };
  }
  if (status === 409 && code === "already_enrolled") {
    return { kind: "already" };
  }
  if (status === 400 && code === "password_rejected") {
    return { kind: "password", why: changeRefusal(status, body) };
  }
  return status === 429 ? refusal(status, body, retryAfter) : { kind: "retry" };
}
