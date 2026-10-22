// Every word the pages show, in one place so it reads as one voice and can be translated whole. The voice is plain,
// calm and specific: a refusal says what happened and what to do next, never a status number and never blame.

import type { Refusal } from "./flow.ts";

const seconds = new Intl.PluralRules("en");

/** "N second(s)", by the language's plural rules rather than by a count of one. */
function inSeconds(count: number): string {
  return seconds.select(count) === "one" ? `${count} second` : `${count} seconds`;
}

/** The words for where a refusal leaves the user. */
export function refusalText(refused: Refusal): string {
  switch (refused.kind) {
    case "rejected":
      return "That didn't match. Check it and try again.";
    case "expired":
      return "This sign-in has expired. Go back to the application and start again.";
    case "throttled":
      return refused.seconds === null
        ? "Too many attempts. Wait a moment, then try again."
        : `Too many attempts. Try again in ${inSeconds(refused.seconds)}.`;
    case "retry":
      return "Something went wrong on our side. Try again in a moment.";
  }
}

const SCOPES: Readonly<Record<string, string>> = {
  openid: "Confirmation that you signed in, and who you are to this application",
  profile: "Your name and basic profile details",
  email: "Your email address and whether it is verified",
  offline_access: "Access while you are signed out or not using it",
};

/** A scope in the user's terms where this server knows it, the scope itself where it does not. */
export function describeScope(scope: string): string {
  return Object.hasOwn(SCOPES, scope) ? (SCOPES[scope] ?? scope) : scope;
}

/** The words each page shows, by place. */
export const TEXT = {
  starting: "Preparing your sign-in.",
  missing: "This page needs a sign-in to continue. Go back to the application and start again.",
  passkeyCancelled: "The passkey wasn't used. Try again, or sign in another way.",
  emailRequired: "Enter the email address you signed up with.",
  passwordRequired: "Enter your password.",
  codeRequired: "Enter the 6-digit code from your authenticator app.",
  recoveryRequired: "Enter one of your recovery codes.",
  continuing: "Signed in. Taking you back to the application.",
  consentLoading: "Checking what the application asks for.",
  consentNothing: "This application asks for nothing new.",
  allowed: "Access allowed. Taking you back to the application.",
  denied: "Access denied. Taking you back to the application.",
} as const;

const METHODS: Readonly<Record<string, string>> = {
  pwd: "Password",
  totp: "Authenticator app",
  recovery: "Recovery code",
  passkey: "Passkey",
  "passkey-uv": "Passkey",
};

/** How a session signed in, in the user's terms, each way named once. */
export function describeMethods(methods: readonly string[]): string {
  const named = methods.map((method) => (Object.hasOwn(METHODS, method) ? (METHODS[method] ?? method) : method));
  return new Intl.ListFormat("en", { type: "conjunction" }).format([...new Set(named)]);
}

const moment = /* @__PURE__ */ new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });

/** A Unix time in seconds as the user's local date and time. */
export function when(unixSeconds: number): string {
  return moment.format(new Date(unixSeconds * 1000));
}

const codes = /* @__PURE__ */ new Intl.PluralRules("en");

/** How many recovery codes are left, by the language's plural rules. */
export function codesLeft(count: number): string {
  if (count === 0) {
    return "None left";
  }
  return codes.select(count) === "one" ? "1 code left" : `${count} codes left`;
}

/** The words the account page shows, by place. */
export const ACCOUNT_TEXT = {
  loading: "Loading your account.",
  missing: "This page could not find its account. Check the address and try again.",
  unreadable: "Your account could not be loaded. Try again in a moment.",
  signedOut: "You're not signed in here. Sign in to an application that uses this account, then come back.",
  verified: "Verified",
  unverified: "Not verified",
  set: "Set",
  notSet: "Not set",
  on: "On",
  off: "Off",
  noPasskeys: "No passkeys yet.",
  noSessions: "No other sessions.",
  noGrants: "No applications have access.",
  thisSession: "this session",
  ended: "Signed out on that session.",
  everywhereConfirm:
    "This signs you out on every device, this one included. " +
    "Applications keep access only until their current tokens expire.",
  everywhereDone: "Signed out everywhere.",
  revoked: (client: string, endBy: number) =>
    `Removed ${client}'s access. Anything it already holds stops working by ${when(endBy)}.`,
  notRevoked: "That access was already removed.",
} as const;
