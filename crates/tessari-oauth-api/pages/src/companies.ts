// The companies view of the system console: the directory a page at a time, a form creating a company, and a move
// per company between served and not. Suspending stops a whole company being served, so it names the company, says
// so and asks for the id typed out; resuming serves it again and asks only for the reason. The company this console
// serves is never offered a suspension, and the server refuses one for it whatever is offered.

import { confirmedBy } from "./console-read.ts";
import { companyRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, button, heading, labelled, link, make, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import {
  type Company,
  companiesPath,
  companyIdOf,
  companyNameOf,
  readCompaniesPage,
  readCompany,
} from "./companies-read.ts";

/** A company's state as a badge carrying its word, never its colour alone. */
function statusBadge(company: Company): HTMLSpanElement {
  const badge = make("span", "badge", company.status);
  badge.dataset["state"] = company.status === "active" ? "ok" : "warn";
  return badge;
}

/** A date in seconds since the epoch, as the operator's locale writes a day. */
function day(seconds: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(seconds * 1000));
}

/** The form creating a company; `created` redraws the view with the outcome. */
function createForm(screen: Screen, created: (message: string) => void): HTMLFormElement {
  const keyFor = keys();
  const id = make("input", "mono");
  id.type = "text";
  id.autocomplete = "off";
  id.spellcheck = false;
  const name = make("input", "");
  name.type = "text";
  name.autocomplete = "off";
  name.maxLength = 100;
  const reason = reasonField("company-reason");
  const said = notice();
  const submit = make("button", "primary", "Create the company");
  submit.type = "submit";
  const form = make(
    "form",
    "change-form",
    make("h2", "", "Create a company"),
    labelled("company-id", "Id (lowercase letters, digits and inner hyphens; it becomes the issuer path)", id),
    labelled("company-name", "Name people see", name),
    reason.row,
    said,
    submit,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    said.hidden = true;
    const chosen = companyIdOf(id.value);
    const named = companyNameOf(name.value);
    if (chosen === null || named === null) {
      const wrong = chosen === null ? id : name;
      said.textContent = chosen === null
        ? "Give an id of 1 to 63 lowercase letters, digits and inner hyphens."
        : "Give a name of 1 to 100 characters.";
      said.hidden = false;
      wrong.setAttribute("aria-invalid", "true");
      wrong.focus();
      return;
    }
    id.removeAttribute("aria-invalid");
    name.removeAttribute("aria-invalid");
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    submit.disabled = true;
    void change("api/companies", keyFor, { id: chosen, name: named, reason: why }).then((answer) => {
      submit.disabled = false;
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readCompany(answer.body) : null;
      if (made !== null) {
        created(`Company ${made.id} created; its issuer is served now (${made.status}).`);
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "That company", companyRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  return form;
}

/** The directory as a table, each company with its move; `moved` redraws the view with the outcome. */
function directory(
  screen: Screen,
  own: string,
  companies: readonly Company[],
  moved: (message: string) => void,
): Node[] {
  const keyFor = keys();
  const reason = reasonField("move-reason");
  const said = notice();
  const question = make("p", "");
  const typed = make("input", "mono");
  typed.type = "text";
  typed.autocomplete = "off";
  typed.spellcheck = false;
  const typedRow = labelled("move-company", "Type the company id to confirm", typed);
  let target: Company | null = null;
  const go = make("button", "danger", "");
  go.type = "button";
  const confirmPanel = make("div", "confirm", question, typedRow, reason.row, said);
  confirmPanel.hidden = true;

  const ask = (company: Company): void => {
    target = company;
    const suspending = company.status === "active";
    question.replaceChildren(
      suspending ? "Suspend " : "Resume ",
      make("code", "", company.id),
      suspending
        ? "? Its sign-in, its tokens and its console stop being served, so no application can sign anyone in "
          + "through it until it is resumed."
        : "? Its sign-in, tokens and console are served again.",
    );
    typedRow.hidden = !suspending;
    // Serving a company again restores what it had, so only a suspension carries the danger colour.
    go.textContent = suspending ? "Suspend the company" : "Resume the company";
    go.className = suspending ? "danger" : "primary";
    typed.value = "";
    said.hidden = true;
    confirmPanel.hidden = false;
    (suspending ? typed : reason.input).focus();
  };

  const head = make(
    "tr",
    "",
    make("th", "", "Id"),
    make("th", "", "Name"),
    make("th", "", "State"),
    make("th", "", "Created"),
    make("th", "", "Created by"),
    make("th", "", "Change"),
  );
  for (const cell of head.children) {
    cell.setAttribute("scope", "col");
  }
  const body = make("tbody", "");
  for (const company of companies) {
    const offered = company.id !== own && (company.status === "active" || company.status === "suspended");
    const action = offered
      ? button(company.status === "active" ? "Suspend" : "Resume", "quiet", () => ask(company))
      : "";
    body.append(
      make(
        "tr",
        "",
        make("td", "", make("code", "", company.id)),
        make("td", "", company.name),
        make("td", "", statusBadge(company)),
        make("td", "", day(company.createdAt)),
        make("td", "", make("code", "", company.createdBy)),
        make("td", "", action),
      ),
    );
  }

  go.addEventListener("click", () => {
    const chosen = target;
    const why = reasonIn(reason.input, said);
    if (chosen === null || why === null) {
      return;
    }
    const suspending = chosen.status === "active";
    if (suspending && !confirmedBy(typed.value, chosen.id)) {
      said.textContent = `Type ${chosen.id} exactly to confirm.`;
      said.hidden = false;
      typed.setAttribute("aria-invalid", "true");
      typed.focus();
      return;
    }
    typed.removeAttribute("aria-invalid");
    const path = `api/companies/${encodeURIComponent(chosen.id)}/${suspending ? "suspend" : "resume"}`;
    void change(path, keyFor, { reason: why }).then((answer) => {
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readCompany(answer.body) : null;
      if (made !== null) {
        moved(`Company ${made.id} is now ${made.status}.`);
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "That company", companyRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  const keep = button("Leave it as it is", "secondary", () => {
    confirmPanel.hidden = true;
    target = null;
  });
  confirmPanel.append(make("div", "actions", go, keep));
  return [make("table", "grid", make("thead", "", head), body), confirmPanel];
}

/** The companies view of the console serving `own`, after `after`, with `message` said once it is drawn. */
export async function companiesView(screen: Screen, own: string, after: string | null, message = ""): Promise<void> {
  say("Loading the companies.");
  const answer = await call("GET", companiesPath(after));
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Companies", answer, "That page");
    return;
  }
  const page = readCompaniesPage(answer.body);
  if (page === null) {
    unreadable(screen, "Companies");
    return;
  }
  const redraw = (said: string): void => void companiesView(screen, own, after, said);
  const parts: Node[] = [
    heading("Companies"),
    make("p", "lead", "Every company this node serves, each its own issuer with its own users, clients and keys."),
  ];
  if (page.companies.length === 0) {
    parts.push(make("p", "empty", after === null ? "No companies yet." : "No more companies."));
  } else {
    parts.push(...directory(screen, own, page.companies, redraw));
  }
  const paging = make("p", "paging");
  if (after !== null) {
    paging.append(link("#/companies", "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`#/companies?${new URLSearchParams({ after: page.next }).toString()}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  parts.push(createForm(screen, redraw));
  show(screen.view, ...parts);
  say(message);
}
