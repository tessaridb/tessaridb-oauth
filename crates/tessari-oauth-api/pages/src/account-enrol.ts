// The account page's additions and removals of sign-in methods: an authenticator app, enrolled from a key shown
// once and confirmed by a code from it, and passkeys, created by the browser against a challenge issued to this
// account and removed one at a time. Each needs a recent sign-in, and the server refuses taking away the last way in.

import type { Followups } from "./account-factors.ts";
import { ACCOUNT_TEXT, refusalText } from "./copy.ts";
import { type Answer, call, element, fieldError, say } from "./dom.ts";
import { type EnrolRefusal, enrolRefusal, readAppSecret, readRegistration } from "./enrolment-read.ts";
import { refusal, toBase64url } from "./flow.ts";

/** Say why `answer` refused, or move to the signed-out state. */
function refused(answer: Answer, followups: Followups): void {
  const why: EnrolRefusal = enrolRefusal(answer.status, answer.body);
  switch (why) {
    case "signed-out":
      followups.signedOut();
      break;
    case "reauthenticate":
      say(ACCOUNT_TEXT.reauthenticate);
      break;
    case "already-enrolled":
      say(ACCOUNT_TEXT.alreadyEnrolled);
      break;
    case "start-again":
    case "code-rejected":
      say(ACCOUNT_TEXT.appStartAgain);
      break;
    case "last-method":
      say(ACCOUNT_TEXT.lastMethod);
      break;
    case "not-accepted":
      say(ACCOUNT_TEXT.passkeyNotAccepted);
      break;
    case "other":
      say(refusalText(refusal(answer.status, answer.body, answer.retryAfter)));
      break;
  }
}

/** Wire the authenticator app's enrolment, offered only to an account that has none. */
export function wireApp(base: string, holdsApp: boolean, followups: Followups): void {
  const open = element("app-open", HTMLButtonElement);
  const form = element("app-form", HTMLFormElement);
  const input = element("app-code", HTMLInputElement);
  const secret = element("app-secret", HTMLElement);
  const link = element("app-link", HTMLAnchorElement);
  open.hidden = holdsApp;
  const close = (): void => {
    input.value = "";
    secret.textContent = "";
    link.removeAttribute("href");
    fieldError(input, null);
    form.hidden = true;
  };
  open.addEventListener("click", () => {
    void (async () => {
      open.disabled = true;
      const answer = await call("POST", `${base}/totp/begin`, {});
      open.disabled = false;
      const begun = answer.ok ? readAppSecret(answer.body) : null;
      if (begun === null) {
        refused(answer, followups);
        return;
      }
      secret.textContent = begun.secret;
      link.href = begun.uri;
      form.hidden = false;
      open.hidden = true;
      input.focus();
    })();
  });
  element("app-cancel", HTMLButtonElement).addEventListener("click", () => {
    close();
    open.hidden = false;
    open.focus();
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      const code = input.value.replaceAll(" ", "");
      if (!/^\d{6}$/.test(code)) {
        fieldError(input, ACCOUNT_TEXT.appCodeRequired);
        return;
      }
      const answer = await call("POST", `${base}/totp/confirm`, { code });
      close();
      if (!answer.ok) {
        // A wrong code ends the attempt on the server, so the key is gone and the user starts again.
        refused(answer, followups);
        open.hidden = false;
        open.focus();
        return;
      }
      say(ACCOUNT_TEXT.appAdded);
      await followups.changed();
    })();
  });
}

/** Wire adding a passkey, offered only where the browser can create one. */
export function wirePasskeyAdd(base: string, followups: Followups): void {
  const add = element("passkey-add", HTMLButtonElement);
  add.hidden = typeof window.PublicKeyCredential !== "function";
  add.addEventListener("click", () => {
    void (async () => {
      add.disabled = true;
      try {
        await addPasskey(base, followups);
      } finally {
        add.disabled = false;
      }
    })();
  });
}

async function addPasskey(base: string, followups: Followups): Promise<void> {
  const asked = await call("POST", `${base}/passkeys/options`, {});
  const options = asked.ok ? readRegistration(asked.body) : null;
  if (options === null) {
    refused(asked, followups);
    return;
  }
  let created: Credential | null;
  try {
    created = await navigator.credentials.create({
      publicKey: {
        challenge: options.challenge,
        rp: { id: options.rpId, name: "TessariDB" },
        user: { id: options.userId, name: options.userName, displayName: options.userName },
        pubKeyCredParams: options.algorithms.map((alg) => ({ type: "public-key" as const, alg })),
        excludeCredentials: options.exclude.map((id) => ({ type: "public-key" as const, id })),
        authenticatorSelection: { residentKey: "required", userVerification: options.userVerification },
        attestation: "none",
        timeout: options.timeout,
      },
    });
  } catch {
    created = null;
  }
  if (!(created instanceof PublicKeyCredential) || !(created.response instanceof AuthenticatorAttestationResponse)) {
    say(ACCOUNT_TEXT.passkeyCancelled);
    return;
  }
  const answer = await call("POST", `${base}/passkeys/register`, {
    client_data_json: toBase64url(new Uint8Array(created.response.clientDataJSON)),
    attestation_object: toBase64url(new Uint8Array(created.response.attestationObject)),
  });
  if (!answer.ok) {
    refused(answer, followups);
    return;
  }
  say(ACCOUNT_TEXT.passkeyAdded);
  await followups.changed();
}

/** Remove the passkey `id`, pressed from its row. */
export async function removePasskey(
  base: string,
  id: string,
  pressed: HTMLButtonElement,
  followups: Followups,
): Promise<void> {
  pressed.disabled = true;
  const answer = await call("POST", `${base}/passkeys/remove`, { id });
  pressed.disabled = false;
  if (!answer.ok) {
    refused(answer, followups);
    return;
  }
  say(ACCOUNT_TEXT.passkeyRemoved);
  await followups.changed();
}
