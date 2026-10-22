// The users views. Operators arrive with an address, so the list leads with a lookup by exact address; without one
// it pages through the company's accounts in id order behind the server's cursor, with no total. An address is shown
// masked as the server sends it.

import { readRefusal } from "./console-read.ts";
import { refusalText } from "./console-copy.ts";
import { type Screen, heading, labelled, link, make, show } from "./console-dom.ts";
import { type Answer, call, say } from "./dom.ts";
import { actionsFor, openForm } from "./users-actions.ts";
import { type User, readUser, readUsersPage, usersPath } from "./users-read.ts";

/** What the next account view says once drawn: the outcome of the change that led to it. */
let pending = "";

/** Draw `answer`'s refusal on `screen`, or hand over to signing in when the session has ended. */
export function refusedOn(screen: Screen, title: string, answer: Answer, what: string): void {
  const refusal = readRefusal(answer.status, answer.body, answer.retryAfter);
  if (refusal.kind === "signed_out") {
    screen.signedOut();
    return;
  }
  show(screen.view, heading(title), make("p", "notice", refusalText(refusal, what)));
  say("");
}

/** Say on `screen` that the server answered in a shape the console cannot read. */
export function unreadable(screen: Screen, title: string): void {
  show(screen.view, heading(title), make("p", "notice", "The server answered in a shape the console cannot read."));
  say("");
}

/** An account's state as a badge carrying its word, never its colour alone. */
export function statusBadge(user: User): HTMLSpanElement {
  const badge = make("span", "badge", user.status === "active" ? "Active" : "Disabled");
  badge.dataset["state"] = user.status === "active" ? "ok" : "warn";
  return badge;
}

/** The lookup form, which moves the address to the view's own URL so the view can be shared. */
function lookup(email: string | null): HTMLFormElement {
  const input = make("input", "");
  input.type = "email";
  input.name = "email";
  input.autocomplete = "off";
  input.value = email ?? "";
  const find = make("button", "secondary", "Find");
  find.type = "submit";
  const form = make("form", "inline-form", labelled("users-email", "Find by exact address", input), find);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const typed = input.value.trim();
    location.hash = typed === "" ? "#/users" : `#/users?${new URLSearchParams({ email: typed }).toString()}`;
  });
  return form;
}

/** The accounts as a table: address, whether it is verified, state, and a link to each. */
function table(users: readonly User[]): HTMLTableElement {
  const head = make(
    "tr",
    "",
    make("th", "", "Address"),
    make("th", "", "Verified"),
    make("th", "", "State"),
    make("th", "", "Account"),
  );
  for (const cell of head.children) {
    cell.setAttribute("scope", "col");
  }
  const body = make("tbody", "");
  for (const user of users) {
    body.append(
      make(
        "tr",
        "",
        make("td", "", make("code", "", user.email)),
        make("td", "", user.emailVerified ? "Yes" : "No"),
        make("td", "", statusBadge(user)),
        make("td", "", link(`#/users/${encodeURIComponent(user.user)}`, user.user, "mono-link")),
      ),
    );
  }
  return make("table", "grid", make("thead", "", head), body);
}

/** The users list for a route: the account an exact `email` names, or a page after `after`. */
export async function usersView(screen: Screen, email: string | null, after: string | null): Promise<void> {
  say("Loading accounts.");
  const answer = await call("GET", usersPath({ email, after }));
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Users", answer, "That account");
    return;
  }
  const page = readUsersPage(answer.body);
  if (page === null) {
    unreadable(screen, "Users");
    return;
  }
  const looking = email !== null && email.trim() !== "";
  const parts: Node[] = [heading("Users"), lookup(email)];
  if (page.users.length === 0) {
    parts.push(
      make(
        "p",
        "empty",
        looking ? "No account in this company has this address." : "This company has no accounts on this page.",
      ),
    );
  } else {
    parts.push(table(page.users));
  }
  const paging = make("p", "paging");
  if (looking || after !== null) {
    paging.append(link("#/users", looking ? "Show all accounts" : "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`#/users?${new URLSearchParams({ after: page.next }).toString()}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  parts.push(
    openForm(screen, (user) => {
      pending = "Account opened.";
      location.hash = `#/users/${encodeURIComponent(user)}`;
    }),
  );
  show(screen.view, ...parts);
  say("");
}

/** One account by its id, with `message` said once it is drawn. */
export async function userView(screen: Screen, id: string, message = ""): Promise<void> {
  say("Loading the account.");
  const answer = await call("GET", `api/users/${encodeURIComponent(id)}`);
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Account", answer, "That account");
    return;
  }
  const user = readUser(answer.body);
  if (user === null) {
    unreadable(screen, "Account");
    return;
  }
  const address = make("code", "", user.email);
  const facts = make(
    "dl",
    "facts",
    make("dt", "", "Account"),
    make("dd", "", make("code", "", user.user)),
    make("dt", "", "Address"),
    make("dd", "", address),
    make("dt", "", "Verified"),
    make("dd", "", user.emailVerified ? "Yes" : "No"),
    make("dt", "", "State"),
    make("dd", "", statusBadge(user)),
  );
  const redraw = (said: string): void => void userView(screen, id, said);
  show(
    screen.view,
    heading("Account"),
    facts,
    actionsFor(screen, user, address, redraw),
    make("p", "paging", link("#/users", "Back to users")),
  );
  say(message !== "" ? message : pending);
  pending = "";
}
