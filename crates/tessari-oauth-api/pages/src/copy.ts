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
  signedOut: "You're not signed in here. Sign in to see and manage your account.",
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
  reauthenticate:
    "Changing how you sign in needs a sign-in from the last ten minutes. Sign in again, then try once more.",
  passwordHintAlone: "At least 15 characters. A few unrelated words work well.",
  passwordHintWithApp: "At least 8 characters, since you also use an authenticator app.",
  passwordRequired: "Enter a new password.",
  passwordTooShort: "That password is too short for this account.",
  passwordTooLong: "That password is too long. Use 64 characters or fewer.",
  passwordNotPrintable: "That password has a character that can't be typed. Remove it and try again.",
  passwordGuessable: "That password is too easy to guess. Don't use your email address.",
  passwordRejected: "That password can't be used. Choose a longer one that isn't your email address.",
  passwordChanged: "Password changed. You were signed out on your other devices.",
  codesIssued: "New recovery codes are ready. Your old ones no longer work.",
  alreadyEnrolled: "This account already has an authenticator app.",
  appCodeRequired: "Enter the 6-digit code your app shows for this account.",
  appStartAgain: "That code didn't match, so the key was discarded. Set up the app again to get a new key.",
  appAdded: "Authenticator app turned on. You were signed out on your other devices.",
  lastMethod: "That's the last way to sign in to this account. Add another one before removing it.",
  appNotOffered: "Your organization doesn't use authenticator apps, so one can't be set up here.",
  keepOne:
    "Your organization requires a second way to confirm it's you. Add a passkey or an app before removing this one.",
  enrolDue:
    "Your organization requires a second way to confirm it's you. " +
    "Add a passkey or an authenticator app to keep signing in to its applications.",
  appRemoved: "Authenticator app turned off. You were signed out on your other devices.",
  passkeyNotAccepted: "That passkey couldn't be added. Try again, or use a different device.",
  passkeyCancelled: "No passkey was added.",
  passkeyAdded: "Passkey added. You were signed out on your other devices.",
  passkeyRemoved: "Passkey removed. You were signed out on your other devices.",
} as const;
