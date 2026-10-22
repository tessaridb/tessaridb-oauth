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
