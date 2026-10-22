// What the account page reads when it adds an authenticator app or a passkey, kept apart from the document so it
// can be tested without a browser. Every answer is read as unknown and narrowed.

import { field, fromBase64url, strings } from "./flow.ts";

/** An app's secret, shown once: in base32 for typing, and as the key URI an app scans. */
export interface AppSecret {
  secret: string;
  uri: string;
}

/** What the browser is asked for when it creates a passkey for this account. */
export interface Registration {
  challenge: Uint8Array<ArrayBuffer>;
  rpId: string;
  userId: Uint8Array<ArrayBuffer>;
  userName: string;
  exclude: Uint8Array<ArrayBuffer>[];
  algorithms: number[];
  userVerification: "required" | "preferred";
  timeout: number;
}

/** Why adding or removing a sign-in method was refused, in the terms the page explains it. */
export type EnrolRefusal =
  | "already-enrolled"
  | "start-again"
  | "code-rejected"
  | "last-method"
  | "not-accepted"
  | "reauthenticate"
  | "signed-out"
  | "other";

/** `POST account/api/totp/begin`. */
export function readAppSecret(answer: unknown): AppSecret | null {
  const secret = field(answer, "secret");
  const uri = field(answer, "uri");
  if (typeof secret !== "string" || secret === "" || typeof uri !== "string" || !uri.startsWith("otpauth://totp/")) {
    return null;
  }
  return { secret, uri };
}

/** Bytes from base64url `value`, or null when it is not non-empty base64url. */
function bytes(value: unknown): Uint8Array<ArrayBuffer> | null {
  const decoded = typeof value === "string" ? fromBase64url(value) : null;
  return decoded === null || decoded.length === 0 ? null : decoded;
}

/** `POST account/api/passkeys/options`. */
export function readRegistration(answer: unknown): Registration | null {
  const challenge = bytes(field(answer, "challenge"));
  const rpId = field(answer, "rp_id");
  const user = field(answer, "user");
  const userId = bytes(field(user, "id"));
  const userName = field(user, "name");
  const excludedIds = strings(field(answer, "exclude"));
  const exclude = excludedIds?.map(bytes) ?? null;
  const algorithms = field(answer, "algorithms");
  const verification = field(answer, "user_verification");
  const timeout = field(answer, "timeout_ms");
  if (
    challenge === null ||
    typeof rpId !== "string" ||
    userId === null ||
    typeof userName !== "string" ||
    exclude === null ||
    !Array.isArray(algorithms) ||
    algorithms.length === 0 ||
    !algorithms.every((algorithm) => Number.isSafeInteger(algorithm)) ||
    (verification !== "required" && verification !== "preferred") ||
    typeof timeout !== "number"
  ) {
    return null;
  }
  const excluded = exclude.filter((id) => id !== null);
  if (excluded.length !== exclude.length) {
    return null;
  }
  return {
    challenge,
    rpId,
    userId,
    userName,
    exclude: excluded,
    algorithms: algorithms.filter((algorithm): algorithm is number => typeof algorithm === "number"),
    userVerification: verification,
    timeout,
  };
}

/** Read a refused enrolment or removal from its `status` and body. */
export function enrolRefusal(status: number, body: unknown): EnrolRefusal {
  const code = field(body, "code");
  switch (code) {
    case "already_enrolled":
      return "already-enrolled";
    case "nothing_pending":
      return "start-again";
    case "code_rejected":
      return "code-rejected";
    case "last_sign_in_method":
      return "last-method";
    case "invalid_request":
      return "not-accepted";
    case "reauthentication_required":
      return status === 401 ? "reauthenticate" : "other";
    case "session_required":
      return status === 401 ? "signed-out" : "other";
    default:
      return "other";
  }
}
