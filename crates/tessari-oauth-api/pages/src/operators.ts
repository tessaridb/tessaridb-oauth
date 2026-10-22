// The operators view: the current grants of the roles the signed-in operator holds, a form granting one of those
// roles for a bounded number of days, and a revocation per grant. Both changes carry a reason; revoking names the
// account and the role before it is made, because it ends that operator's access at once. The server refuses a
// grant to oneself and a role above the company's ceiling whatever is offered here.

import { type Me, type Role } from "./console-read.ts";
import { operatorRefusalText } from "./console-copy.ts";
import {
  change,
  keys,
  notice,
  reasonField,
  reasonIn,
  refusedOn,
  refusedText,
  unreadable,
} from "./console-change.ts";
import { type Screen, button, heading, labelled, link, make, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import { type Grant, daysOf, operatorsPath, readGrantsPage, readRevoked } from "./operators-read.ts";

/** What the days field says when it does not hold 1 to 365 whole days. */
const DAYS_WRONG = "Give a whole number of days from 1 to 365, or leave it empty for 90.";

/** A date in seconds since the epoch, as the operator's locale writes a day. */
function day(seconds: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(seconds * 1000));
}

/** A role picker for `roles`: one pill per role on a row, never a native select. */
function rolePicker(roles: readonly Role[]): { group: HTMLFieldSetElement; chosen: () => Role | null } {
  const group = make("fieldset", "segmented", make("legend", "", "Role"));
  const inputs: [HTMLInputElement, Role][] = [];
  for (const [index, role] of roles.entries()) {
    const input = make("input", "");
    input.type = "radio";
    input.name = "grant-role";
    input.id = `grant-role-${role}`;
    input.value = role;
    input.checked = index === 0;
    const label = make("label", "", role);
    label.htmlFor = input.id;
    group.append(input, label);
    inputs.push([input, role]);
  }
  return { group, chosen: () => inputs.find(([input]) => input.checked)?.[1] ?? null };
}

/** The form granting one of `roles`; `granted` redraws the view with the outcome. */
function grantForm(screen: Screen, roles: readonly Role[], granted: (message: string) => void): HTMLFormElement {
  const keyFor = keys();
  const account = make("input", "mono");
  account.type = "text";
  account.required = true;
  account.autocomplete = "off";
  account.spellcheck = false;
  const days = make("input", "");
  days.type = "text";
  days.inputMode = "numeric";
  days.placeholder = "90";
  const picker = rolePicker(roles);
  const reason = reasonField("grant-reason");
  const said = notice();
  const submit = make("button", "primary", "Grant the role");
  submit.type = "submit";
  const form = make(
    "form",
    "change-form",
    make("h2", "", "Grant a role"),
    labelled("grant-account", "Account id", account),
    picker.group,
    labelled("grant-days", "Days it lasts (1 to 365; empty for 90)", days),
    reason.row,
    said,
    submit,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    said.hidden = true;
    const user = account.value.trim();
    const role = picker.chosen();
    const valid = daysOf(days.value);
    if (user === "" || role === null || valid === null) {
      const wrong = user === "" ? account : days;
      said.textContent = user === "" ? "Give the id of the account to grant the role to." : DAYS_WRONG;
      said.hidden = false;
      wrong.setAttribute("aria-invalid", "true");
      wrong.focus();
      return;
    }
    account.removeAttribute("aria-invalid");
    days.removeAttribute("aria-invalid");
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    submit.disabled = true;
    const path = `api/operators/${encodeURIComponent(user)}/grants/${encodeURIComponent(role)}`;
    void change(path, keyFor, { reason: why, valid_days: valid }).then((answer) => {
      submit.disabled = false;
      if (!screen.live()) {
        return;
      }
      if (answer.ok) {
        granted(`Granted ${role} to ${user} for ${valid} days.`);
        return;
      }
      const text = refusedText(screen, answer, "That account", operatorRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  return form;
}

/** The grants as a table, each with a revocation that asks first; `revoked` redraws the view with the outcome. */
function grantsTable(screen: Screen, grants: readonly Grant[], revoked: (message: string) => void): Node[] {
  const keyFor = keys();
  const reason = reasonField("revoke-reason");
  const said = notice();
  const question = make("p", "");
  let target: Grant | null = null;
  const confirmPanel = make("div", "confirm", question, reason.row, said);
  confirmPanel.hidden = true;
  const head = make(
    "tr",
    "",
    make("th", "", "Account"),
    make("th", "", "Role"),
    make("th", "", "Granted by"),
    make("th", "", "Expires"),
    make("th", "", "Reason"),
    make("th", "", "Change"),
  );
  for (const cell of head.children) {
    cell.setAttribute("scope", "col");
  }
  const body = make("tbody", "");
  for (const grant of grants) {
    const revoke = button("Revoke", "quiet", () => {
      target = grant;
      question.replaceChildren(
        "Revoke ",
        make("code", "", grant.role),
        " from ",
        make("code", "", grant.user),
        "? Their console stops offering what the role allows at once; another grant restores it.",
      );
      said.hidden = true;
      confirmPanel.hidden = false;
      reason.input.focus();
    });
    body.append(
      make(
        "tr",
        "",
        make("td", "", make("code", "", grant.user)),
        make("td", "", make("span", "pill", grant.role)),
        make("td", "", make("code", "", grant.grantedBy)),
        make("td", "", grant.expiresAt === null ? "Never" : day(grant.expiresAt)),
        make("td", "", grant.reason),
        make("td", "", revoke),
      ),
    );
  }
  const keep = button("Keep it", "secondary", () => {
    confirmPanel.hidden = true;
    target = null;
  });
  const confirm = button("Revoke the role", "danger", () => {
    const chosen = target;
    const why = reasonIn(reason.input, said);
    if (chosen === null || why === null) {
      return;
    }
    const path = `api/operators/${encodeURIComponent(chosen.user)}/grants/${encodeURIComponent(chosen.role)}/revoke`;
    void change(path, keyFor, { reason: why }).then((answer) => {
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readRevoked(answer.body) : null;
      if (made !== null) {
        revoked(`Revoked ${made.role} from ${made.user}.`);
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "That grant", operatorRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  confirmPanel.append(make("div", "actions", confirm, keep));
  return [make("table", "grid", make("thead", "", head), body), confirmPanel];
}

/** The operators view for `who`, on the grants page after `after`, with `message` said once it is drawn. */
export async function operatorsView(screen: Screen, who: Me, after: string | null, message = ""): Promise<void> {
  say("Loading the operators.");
  const answer = await call("GET", operatorsPath(after));
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Operators", answer, "That page");
    return;
  }
  const page = readGrantsPage(answer.body);
  if (page === null) {
    unreadable(screen, "Operators");
    return;
  }
  const redraw = (said: string): void => void operatorsView(screen, who, after, said);
  const parts: Node[] = [
    heading("Operators"),
    make("p", "lead", "Current grants of the roles you hold. Every grant expires; nobody grants a role to themselves."),
  ];
  if (page.grants.length === 0) {
    parts.push(make("p", "empty", after === null ? "Nobody holds your roles yet." : "No more grants."));
  } else {
    parts.push(...grantsTable(screen, page.grants, redraw));
  }
  const paging = make("p", "paging");
  if (after !== null) {
    paging.append(link("#/operators", "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`#/operators?${new URLSearchParams({ after: page.next }).toString()}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  parts.push(
    who.roles.length > 0
      ? grantForm(screen, who.roles, redraw)
      : make("p", "muted", "You hold no roles, so you can grant none."),
  );
  show(screen.view, ...parts);
  say(message);
}
