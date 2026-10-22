// What the sign-in policy view decides, kept apart from the document: the two-factor policy as the server names it,
// what changing it does to every account of the company.

import { field } from "./flow.ts";

/** The company's two-factor policy, as the server names it. */
export type Policy = "off" | "optional" | "required";

/** The policies in the order the console offers them, weakest first. */
export const POLICIES: readonly Policy[] = ["off", "optional", "required"];

function isPolicy(name: unknown): name is Policy {
  return POLICIES.some((policy) => policy === name);
}

/** `GET api/policy/two-factor`'s answer, or null for any other shape. */
export function readPolicy(body: unknown): Policy | null {
  const policy = field(body, "policy");
  return isPolicy(policy) ? policy : null;
}

/** What moving from `from` to `to` does to the company's accounts, or null when nothing changes. */
export function policyConsequence(from: Policy, to: Policy): string | null {
  if (from === to) {
    return null;
  }
  switch (to) {
    case "required":
      return "Every account of this company must hold a second factor. Accounts without one enrol it at their next "
        + "sign-in before they can continue.";
    case "optional":
      return from === "required"
        ? "Accounts may stop using a second factor; those that keep one still sign in with it."
        : "Accounts may add a second factor and then sign in with it; nobody is made to.";
    case "off":
      return "No account of this company is asked for a second factor: a password alone signs in, including for "
        + "accounts that enrolled one.";
  }
}
