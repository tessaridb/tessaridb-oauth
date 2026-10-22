// What the console says about a refusal: what happened and what the operator can do next, never a raw status.

import type { ConsoleRefusal } from "./console-read.ts";

/** The words for `refusal`; `what` names the thing that was not found. */
export function refusalText(refusal: ConsoleRefusal, what: string): string {
  switch (refusal.kind) {
    case "signed_out":
      return "Your console session has ended. Sign in again.";
    case "role":
      return "Your operator roles do not include this. Ask an operator who holds the role to grant it.";
    case "not_found":
      return `${what} was not found in this company.`;
    case "throttled":
      return refusal.seconds === null
        ? "Too many requests from here. Wait a moment and try again."
        : `Too many requests from here. Try again in ${refusal.seconds} seconds.`;
    case "refused":
      return `The server refused this (${refusal.code}).`;
    case "failed":
      return "The server did not answer. Try again.";
  }
}
