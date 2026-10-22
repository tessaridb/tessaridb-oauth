// The sign-in policy view: the company's two-factor policy, and a change to it. A change reaches every account of
// the company, so before it is sent the view says what it does and asks for the company's id typed out, beside the
// reason. The change names the policy the operator saw, and the server refuses it if someone changed it meanwhile.

import { changeRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, button, heading, labelled, make, segmented, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import { POLICIES, type Policy, confirmedBy, policyConsequence, readPolicy } from "./policy-read.ts";

const PATH = "api/policy/two-factor";

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

/** The sign-in policy view for `company`, with `message` said once it is drawn. */
export async function policyView(screen: Screen, company: string, message = ""): Promise<void> {
  say("Loading the policy.");
  const answer = await call("GET", PATH);
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Sign-in policy", answer, "The policy");
    return;
  }
  const current = readPolicy(answer.body);
  if (current === null) {
    unreadable(screen, "Sign-in policy");
    return;
  }
  const redraw = (said: string): void => void policyView(screen, company, said);
  show(
    screen.view,
    heading("Sign-in policy"),
    make("p", "lead", "Whether accounts of this company sign in with a second factor. Operators always do."),
    make("dl", "facts", make("dt", "", "Two-factor"), make("dd", "", badge(current))),
    changeForm(screen, company, current, redraw),
  );
  say(message);
}
