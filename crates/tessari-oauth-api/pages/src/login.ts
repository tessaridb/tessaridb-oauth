// The sign-in page. It begins a sign-in for the authorization named in its address, then shows whichever step the
// server says comes next, until the server says the sign-in is complete and where the authorization continues.
// Everything the user typed stays in place when a step is refused.

import { TEXT, refusalText } from "./copy.ts";
import { type Answer, call, element, fieldError, say } from "./dom.ts";
import {
  type Step,
  apiBase,
  readCompleted,
  readNext,
  readPasskeyOptions,
  refusal,
  toBase64url,
} from "./flow.ts";

const STEP_FORMS: readonly Step[] = ["identify", "first_factor", "second_factor"];

const email = element("email", HTMLInputElement);
const password = element("password", HTMLInputElement);
const code = element("code", HTMLInputElement);
const recovery = element("recovery", HTMLInputElement);
const passkeyOption = element("passkey-option", HTMLDivElement);
const passkeyButton = element("passkey", HTMLButtonElement);
const passkeys = typeof window.PublicKeyCredential === "function";
let usingRecovery = false;

/** Disable or enable every button while a step is on its way, so a double press sends nothing twice. */
function busy(on: boolean): void {
  for (const button of document.querySelectorAll("button")) {
    button.disabled = on;
  }
}

/** Hide every step. */
function hideSteps(): void {
  for (const step of STEP_FORMS) {
    element(step, HTMLFormElement).hidden = true;
  }
  passkeyOption.hidden = true;
}

/** Show `step` and put the keyboard in its first field. */
function show(step: Step): void {
  hideSteps();
  if (step === "complete") {
    return;
  }
  element(step, HTMLFormElement).hidden = false;
  passkeyOption.hidden = !passkeys;
  passkeyButton.textContent = step === "second_factor" ? "Use a passkey instead" : "Sign in with a passkey";
  say("");
  const first = step === "identify" ? email : step === "first_factor" ? password : usingRecovery ? recovery : code;
  first.focus();
}

/** Act on what the API answered to a step whose field, if any, is `input`. */
function settle(answer: Answer, input: HTMLInputElement | null): void {
  if (answer.ok) {
    const next = readNext(answer.body);
    if (next === "complete") {
      const target = readCompleted(answer.body, location.origin);
      if (target === null) {
        say(refusalText({ kind: "retry" }));
        return;
      }
      hideSteps();
      say(TEXT.continuing);
      location.assign(target);
      return;
    }
    if (next === null) {
      say(refusalText({ kind: "retry" }));
      return;
    }
    show(next);
    return;
  }
  const refused = refusal(answer.status, answer.body, answer.retryAfter);
  if (refused.kind === "expired") {
    hideSteps();
  }
  if (refused.kind === "rejected" && input !== null) {
    fieldError(input, refusalText(refused));
    return;
  }
  say(refusalText(refused));
}

/** Send a step, then act on the answer. */
async function step(base: string, path: string, body: unknown, input: HTMLInputElement | null): Promise<void> {
  busy(true);
  const answer = await call("POST", `${base}/${path}`, body);
  busy(false);
  settle(answer, input);
}

/** Read `input`, or show `missing` on it and answer null when it is empty. */
function value(input: HTMLInputElement, missing: string): string | null {
  const text = input.value.trim();
  fieldError(input, text === "" ? missing : null);
  return text === "" ? null : text;
}

async function passkey(base: string): Promise<void> {
  busy(true);
  const asked = await call("POST", `${base}/passkey/options`);
  const options = asked.ok ? readPasskeyOptions(asked.body) : null;
  if (options === null) {
    busy(false);
    if (asked.ok) {
      say(refusalText({ kind: "retry" }));
    } else {
      settle(asked, null);
    }
    return;
  }
  let credential: Credential | null = null;
  try {
    credential = await navigator.credentials.get({
      publicKey: {
        challenge: options.challenge,
        rpId: options.rpId,
        userVerification: options.userVerification,
        timeout: options.timeout,
        allowCredentials: [],
      },
    });
  } catch {
    credential = null;
  }
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) {
    busy(false);
    say(TEXT.passkeyCancelled);
    return;
  }
  const response = credential.response;
  const bytes = (buffer: ArrayBuffer): string => toBase64url(new Uint8Array(buffer));
  await step(
    base,
    "passkey",
    {
      credential_id: bytes(credential.rawId),
      client_data_json: bytes(response.clientDataJSON),
      authenticator_data: bytes(response.authenticatorData),
      signature: bytes(response.signature),
    },
    null,
  );
}

async function main(): Promise<void> {
  const base = apiBase(location.pathname, "login");
  const interaction = new URLSearchParams(location.search).get("interaction");
  if (base === null || interaction === null || interaction === "") {
    say(TEXT.missing);
    return;
  }
  element("identify", HTMLFormElement).addEventListener("submit", (event) => {
    event.preventDefault();
    const address = value(email, TEXT.emailRequired);
    if (address !== null) {
      element("who", HTMLElement).textContent = address;
      void step(base, "identify", { email: address }, email);
    }
  });
  element("first_factor", HTMLFormElement).addEventListener("submit", (event) => {
    event.preventDefault();
    const typed = value(password, TEXT.passwordRequired);
    if (typed !== null) {
      void step(base, "password", { password: password.value }, password);
    }
  });
  element("second_factor", HTMLFormElement).addEventListener("submit", (event) => {
    event.preventDefault();
    const input = usingRecovery ? recovery : code;
    const typed = value(input, usingRecovery ? TEXT.recoveryRequired : TEXT.codeRequired);
    if (typed !== null) {
      void step(base, usingRecovery ? "recovery" : "totp", { code: typed }, input);
    }
  });
  const reveal = element("reveal", HTMLButtonElement);
  reveal.addEventListener("click", () => {
    const shown = password.type === "text";
    password.type = shown ? "password" : "text";
    reveal.setAttribute("aria-pressed", String(!shown));
    reveal.textContent = shown ? "Show" : "Hide";
  });
  const switcher = element("use-recovery", HTMLButtonElement);
  switcher.addEventListener("click", () => {
    usingRecovery = !usingRecovery;
    element("code-field", HTMLDivElement).hidden = usingRecovery;
    element("recovery-field", HTMLDivElement).hidden = !usingRecovery;
    switcher.textContent = usingRecovery ? "Use your authenticator app instead" : "Use a recovery code instead";
    (usingRecovery ? recovery : code).focus();
  });
  passkeyButton.addEventListener("click", () => {
    void passkey(base);
  });
  if (!passkeys) {
    passkeyOption.hidden = true;
  }
  say(TEXT.starting);
  const begun = await call("POST", `${base}/begin`, { interaction });
  settle(begun, null);
}

void main();
