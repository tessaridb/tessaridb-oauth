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
  profile: "Your name: full, given and family",
  email: "Your email address and whether it is verified",
  offline_access: "Access while you are signed out or not using it",
  groups: "The groups you are in at this company, and the roles they give you",
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

/** The words for a forgotten password, on the sign-in page and on the page its link opens. */
export const RESET_TEXT = {
  sending: "Sending a reset link.",
  sent: "If an account uses that address, we sent it a link to choose a new password. It works for 30 minutes.",
  unavailable: "Password reset by email isn't set up here. Ask your administrator to reset it.",
  invalidLink: "This reset link isn't complete. Open the link from the email again, or ask for a new one.",
  spentLink: "This reset link has expired or was already used. Ask for a new one from the sign-in page.",
  hint: "At least 15 characters, or 8 if you also use an authenticator app. A few unrelated words work well.",
  passwordRequired: "Enter a new password.",
  saving: "Saving your new password.",
  changed:
    "Password changed. You were signed out everywhere. Sign in with your new password; " +
    "your second factor and passkeys are unchanged.",
} as const;

/** The words of the page an enrolment link opens. */
export const ENROL_TEXT = {
  invalidLink: "This link isn't complete. Open the link from the email again.",
  spentLink: "This link has expired or was already used. Ask your administrator for a new one.",
  already: "This account already has a password. Sign in with it, or reset it from the sign-in page.",
  hint: "At least 15 characters. A few unrelated words work well.",
  passwordRequired: "Choose a password.",
  saving: "Saving your password.",
  set: "Your password is set. Sign in with it from the application you were invited to.",
} as const;

/** The words of the address-verification page and of the account page's request for a link. */
export const VERIFY_TEXT = {
  confirming: "Confirming your email address.",
  confirmed: "Email address confirmed",
  confirmedNote: "Your account now shows this address as verified. You can close this page.",
  invalidLink: "This confirmation link isn't complete. Open the link from the email again.",
  spentLink:
    "This confirmation link has expired, was already used, or a newer one was sent. " +
    "Ask for a new one on your account page.",
  sending: "Sending a verification link.",
  sent: "We sent a verification link to your address. It works for 24 hours.",
  unavailable: "Email verification isn't set up here. Ask your administrator.",
} as const;

/** The words the address-change page and the account page's change form show. */
export const EMAIL_TEXT = {
  confirming: "Confirming your new sign-in address.",
  confirmed: "New address confirmed",
  confirmedNote: (effectiveAt: number) =>
    `Your account signs in with this address from ${when(effectiveAt)}, unless the change is cancelled ` +
    "from your current address. You can close this page.",
  cancelPrompt:
    "Someone asked to change the address your account signs in with. If it wasn't you, keep your current address.",
  cancelling: "Cancelling the change.",
  cancelled: "Change cancelled",
  cancelledNote:
    "Your account keeps signing in with this address. If you didn't ask for the change, change your password too.",
  invalidLink: "This link isn't complete. Open the link from the email again.",
  spentLink:
    "This link no longer works: it was already used, a newer request replaced it, or the change already took effect.",
  hint:
    "We'll send a link to the new address. The change takes effect a day after you ask, " +
    "and your current address can cancel it until then.",
  required: "Enter the new address.",
  invalid: "Enter an email address like name@example.com.",
  sending: "Sending a message to the new address.",
  sent: "We sent a message to the new address. Open its link within 24 hours to confirm the change.",
  same: "That's already the address you sign in with.",
  unavailable: "Changing your address isn't set up here. Ask your administrator.",
} as const;

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
  nameHint: "Applications you allow to see your name get these. Leave a field empty to clear it.",
  nameRejected: "A name can be up to 100 characters, with no line breaks or tabs. Shorten it and try again.",
  nameSaved: "Your name is saved. Applications see the change the next time they ask.",
} as const;
