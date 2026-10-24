// The sign-in policy view: the company's two-factor policy, and a change to it. A change reaches every account of
// the company, so before it is sent the view says what it does and asks for the company's id typed out, beside the
// reason. The change names the policy the operator saw, and the server refuses it if someone changed it meanwhile.
// Registration, who may open an account by themselves, is changed the same way and names the revision it read.

import { changeRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, button, heading, labelled, make, segmented, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import { confirmedBy } from "./console-read.ts";
import {
  POLICIES,
  type Policy,
  type Registration,
  domainsFrom,
  domainsRefusal,
  policyConsequence,
  readPolicy,
  readRegistration,
  registrationConsequence,
} from "./policy-read.ts";

const PATH = "api/policy/two-factor";
const REGISTRATION_PATH = "api/policy/registration";
const REGISTRATION: readonly ("closed" | "open")[] = ["closed", "open"];

/** The policy as a badge carrying its word, never its colour alone. */
function badge(policy: Policy): HTMLSpanElement {
  const made = make("span", "badge", policy);
  made.dataset["state"] = policy === "off" ? "warn" : "ok";
  return made;
}

/** The form changing `current`; `redraw` shows the view afresh with a message. */
function changeForm(screen: Screen, company: string, current: Policy, redraw: (message: string) => void): HTMLElement {
  const keyFor = keys();
  const picker = segmented("New policy", "two-factor", POLICIES, current);
  const reason = reasonField("policy-reason");
  const said = notice();
  const consequence = make("p", "");
  const typed = make("input", "mono");
  typed.type = "text";
  typed.autocomplete = "off";
  typed.spellcheck = false;
  const confirmPanel = make(
    "div",
    "confirm",
    consequence,
    labelled("policy-company", `Type the company id ${company} to confirm`, typed),
  );
  confirmPanel.hidden = true;
  // What was reviewed is what is sent: choosing again closes the review, so its consequence is never stale.
  picker.group.addEventListener("change", () => {
    confirmPanel.hidden = true;
  });
  const review = button("Review the change", "primary", () => {
    said.hidden = true;
    const chosen = picker.chosen();
    const effect = chosen === null ? null : policyConsequence(current, chosen);
    if (effect === null) {
      said.textContent = "That is already the policy. Choose another to change it.";
      said.hidden = false;
      return;
    }
    if (reasonIn(reason.input, said) === null) {
      return;
    }
    consequence.textContent = effect;
    confirmPanel.hidden = false;
    typed.focus();
  });
  const apply = button("Change the policy", "danger", () => {
    const chosen = picker.chosen();
    const why = reasonIn(reason.input, said);
    if (chosen === null || why === null) {
      return;
    }
    if (!confirmedBy(typed.value, company)) {
      said.textContent = `Type ${company} exactly to confirm.`;
      said.hidden = false;
      typed.setAttribute("aria-invalid", "true");
      typed.focus();
      return;
    }
    typed.removeAttribute("aria-invalid");
    void change(PATH, keyFor, { expected: current, policy: chosen, reason: why }, "PUT").then((answer) => {
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readPolicy(answer.body) : null;
      if (made !== null) {
        redraw(`The two-factor policy is now ${made}.`);
        return;
      }
      if (answer.status === 409) {
        redraw(changeRefusalText("changed_meanwhile"));
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "The policy");
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  const keep = button("Keep the policy", "secondary", () => {
    confirmPanel.hidden = true;
  });
  confirmPanel.append(make("div", "actions", apply, keep));
  const heading2 = make("h2", "", "Change it");
  return make("section", "change-form", heading2, picker.group, reason.row, said, review, confirmPanel);
}

/** The form changing who may open an account from `current`; `redraw` shows the view afresh with a message. */
function registrationForm(
  screen: Screen,
  company: string,
  current: Registration,
  redraw: (message: string) => void,
): HTMLElement {
  const keyFor = keys();
  const picker = segmented("Registration", "registration", REGISTRATION, current.open ? "open" : "closed");
  const domains = make("textarea", "mono");
  domains.id = "registration-domains";
  domains.rows = 3;
  domains.spellcheck = false;
  domains.value = current.domains.join("\n");
  const domainsLabel = make("label", "", "Address domains, one per line (none: any address)");
  domainsLabel.htmlFor = domains.id;
  const reason = reasonField("registration-reason");
  const said = notice();
  const consequence = make("p", "");
  const typed = make("input", "mono");
  typed.type = "text";
  typed.autocomplete = "off";
  typed.spellcheck = false;
  const confirmPanel = make(
    "div",
    "confirm",
    consequence,
    labelled("registration-company", `Type the company id ${company} to confirm`, typed),
  );
  confirmPanel.hidden = true;
  // What was reviewed is what is sent: editing again closes the review, so its consequence is never stale.
  const unreview = (): void => {
    confirmPanel.hidden = true;
  };
  picker.group.addEventListener("change", unreview);
  domains.addEventListener("input", unreview);
  const chosen = (): { open: boolean; domains: string[] } => ({
    open: picker.chosen() === "open",
    domains: domainsFrom(domains.value),
  });
  const review = button("Review the change", "primary", () => {
    said.hidden = true;
    const effect = registrationConsequence(current, chosen());
    if (effect === null) {
      said.textContent = "That is already the registration policy. Change it to review a change.";
      said.hidden = false;
      return;
    }
    if (reasonIn(reason.input, said) === null) {
      return;
    }
    consequence.textContent = effect;
    confirmPanel.hidden = false;
    typed.focus();
  });
  const apply = button("Change registration", "danger", () => {
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    if (!confirmedBy(typed.value, company)) {
      said.textContent = `Type ${company} exactly to confirm.`;
      said.hidden = false;
      typed.setAttribute("aria-invalid", "true");
      typed.focus();
      return;
    }
    typed.removeAttribute("aria-invalid");
    const body = { revision: current.revision, ...chosen(), reason: why };
    void change(REGISTRATION_PATH, keyFor, body, "PUT").then((answer) => {
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readRegistration(answer.body) : null;
      if (made !== null) {
        redraw(made.open ? "Registration is now open." : "Registration is now closed.");
        return;
      }
      if (answer.status === 409) {
        redraw(changeRefusalText("changed_meanwhile"));
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : domainsRefusal(answer.status, answer.body) ?? refusedText(screen, answer, "The registration policy");
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  const keep = button("Keep registration as it is", "secondary", unreview);
  confirmPanel.append(make("div", "actions", apply, keep));
  return make(
    "section",
    "change-form",
    make("h2", "", "Change registration"),
    picker.group,
    make("div", "field", domainsLabel, domains),
    reason.row,
    said,
    review,
    confirmPanel,
  );
}

/** Who may open an account, in words. */
function registrationFact(registration: Registration): HTMLElement {
  if (!registration.open) {
    const closed = make("span", "badge", "closed");
    closed.dataset["state"] = "ok";
    return closed;
  }
  const open = make("span", "badge", "open");
  open.dataset["state"] = "warn";
  const to = registration.domains.length === 0 ? "any address" : registration.domains.join(", ");
  return make("span", "", open, ` to ${to}`);
}

/** The sign-in policy view for `company`, with `message` said once it is drawn. */
export async function policyView(screen: Screen, company: string, message = ""): Promise<void> {
  say("Loading the policy.");
  const [answer, registered] = await Promise.all([call("GET", PATH), call("GET", REGISTRATION_PATH)]);
  if (!screen.live()) {
    return;
  }
  for (const each of [answer, registered]) {
    if (!each.ok) {
      refusedOn(screen, "Sign-in policy", each, "The policy");
      return;
    }
  }
  const current = readPolicy(answer.body);
  const registration = readRegistration(registered.body);
  if (current === null || registration === null) {
    unreadable(screen, "Sign-in policy");
    return;
  }
  const redraw = (said: string): void => void policyView(screen, company, said);
  show(
    screen.view,
    heading("Sign-in policy"),
    make(
      "p",
      "lead",
      "Whether accounts of this company sign in with a second factor, and who may open one by themselves. "
        + "Operators always use a second factor.",
    ),
    make(
      "dl",
      "facts",
      make("dt", "", "Two-factor"),
      make("dd", "", badge(current)),
      make("dt", "", "Registration"),
      make("dd", "", registrationFact(registration)),
    ),
    changeForm(screen, company, current, redraw),
    registrationForm(screen, company, registration, redraw),
  );
  say(message);
}
