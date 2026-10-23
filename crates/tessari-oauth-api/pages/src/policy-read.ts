// What the sign-in policy view decides, kept apart from the document: the two-factor policy as the server names it,
// what changing it does to every account of the company, and the same for who may open an account by themselves.

import { field, strings } from "./flow.ts";

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

/** Who may open an account of the company by themselves: closed or open, to any address or to these domains only. */
export interface Registration {
  open: boolean;
  domains: string[];
  revision: number;
}

/** `GET api/policy/registration`'s answer, or null for any other shape. */
export function readRegistration(body: unknown): Registration | null {
  const open = field(body, "open");
  const domains = strings(field(body, "domains"));
  const revision = field(body, "revision");
  if (typeof open !== "boolean" || domains === null) {
    return null;
  }
  if (typeof revision !== "number" || !Number.isSafeInteger(revision) || revision < 0) {
    return null;
  }
  return { open, domains, revision };
}

/** The domains typed one per line; blank lines are dropped and the server judges the rest. */
export function domainsFrom(typed: string): string[] {
  return typed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

function sameDomains(left: readonly string[], right: readonly string[]): boolean {
  const lower = (names: readonly string[]): string[] => names.map((name) => name.toLowerCase()).sort();
  const [a, b] = [lower(left), lower(right)];
  return a.length === b.length && a.every((name, at) => name === b[at]);
}

/** What changing `from` to `to` does to who may open an account, or null when nothing changes. */
export function registrationConsequence(
  from: Registration,
  to: { open: boolean; domains: readonly string[] },
): string | null {
  if (from.open === to.open && sameDomains(from.domains, to.domains)) {
    return null;
  }
  if (!to.open) {
    return from.open
      ? "Nobody can open an account of this company by themselves any more; operators still create accounts."
      : "Registration stays closed; the domains are kept for when it opens.";
  }
  const who = to.domains.length === 0
    ? "Anyone with any email address"
    : `Anyone with an address at ${to.domains.join(", ")}`;
  return `${who} can open an account of this company by themselves, and sets its password from a mailed link.`;
}

/** The rule a refused domain list broke, or null when `status` and `body` are some other answer. */
export function domainsRefusal(status: number, body: unknown): string | null {
  const rule = field(body, "message");
  if (status !== 400 || field(body, "code") !== "domains_rejected" || typeof rule !== "string") {
    return null;
  }
  return `The domains were refused: ${rule}.`;
}
