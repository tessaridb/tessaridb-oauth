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

/** The words for a change the server refused with `code`: what happened and what to do next. */
export function changeRefusalText(code: string): string {
  switch (code) {
    case "email_taken":
      return "An account in this company already signs in with this address. Look it up instead.";
    case "already_enrolled":
      return "This account has already set a password, so it needs no enrolment code.";
    case "account_disabled":
      return "This account is disabled. Enable it before issuing an enrolment code.";
    case "changed_meanwhile":
      return "Someone changed this while you were looking. The view now shows it as it is; check it and try again.";
    case "reason_required":
      return "Say why, in 1 to 500 characters.";
    case "idempotency_key_reused":
      return "This form was already used for a different change. Reload the view and try again.";
    case "change_in_progress":
      return "This change is still being made. Wait a moment, then reload the view.";
    case "cross_origin":
      return "The request did not come from this console. Reload the console and try again.";
    default:
      return "The server refused this change. Reload the view and try again.";
  }
}

/** The words for a grant or revocation the server refused with `code`. */
export function operatorRefusalText(code: string): string {
  switch (code) {
    case "self_grant":
      return "No operator grants a role to themselves. Ask another operator who holds the role.";
    case "above_ceiling":
      return "Accounts of this company may not hold this role.";
    case "account_disabled":
      return "This account is disabled. Enable it before granting it a role.";
    case "not_granted":
      return "This account does not hold this role any more. Reload the view to see the current grants.";
    default:
      return changeRefusalText(code);
  }
}

/** The words for a company change the server refused with `code`. */
export function companyRefusalText(code: string): string {
  switch (code) {
    case "company_taken":
      return "A company with this id already exists. Choose another id.";
    case "system_company":
      return "The system company runs this console and is never suspended.";
    case "changed_meanwhile":
      return "This company is no longer in the state the view showed. Reload the view and try again.";
    default:
      return changeRefusalText(code);
  }
}
