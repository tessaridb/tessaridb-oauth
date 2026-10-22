// The clients view: the company's client registrations a page at a time, and a form registering a new one. A public
// client signs nobody's secret and always uses PKCE; a confidential one signs its assertions with the key it
// registers. The console offers nothing else, and the server reads every value again whatever is offered here. The
// server's own console client is listed and marked, and never changed from here.

import { clientRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, heading, labelled, link, make, segmented, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import {
  ALGORITHMS,
  type Client,
  type FormField,
  GRANTS,
  clientsPath,
  readClientsPage,
  readRegistered,
  registrationOf,
} from "./clients-read.ts";

/** What each form field says when it holds something the registration cannot take. */
const WRONG: Record<FormField, string> = {
  id: "Give an id of 1 to 255 visible characters.",
  jwk: "Paste the client's public key as one JSON object (a JWK).",
  algorithm: "Choose the algorithm the client signs with.",
  redirects: "A client using the code flow needs at least one redirect URI.",
  scopes: "Give the scopes as words separated by spaces.",
  grants: "Choose at least one grant; only a confidential client may act as itself.",
};

/** A labelled text area whose value is one entry per line. */
function area(id: string, text: string): { input: HTMLTextAreaElement; row: HTMLDivElement } {
  const input = make("textarea", "mono");
  input.id = id;
  input.rows = 2;
  input.spellcheck = false;
  const label = make("label", "", text);
  label.htmlFor = id;
  return { input, row: make("div", "field", label, input) };
}

/** A set of on-or-off choices drawn as pills, never a native select. */
function toggles(legend: string, name: string, options: readonly string[], on: readonly string[]): {
  group: HTMLFieldSetElement;
  chosen: () => string[];
} {
  const group = make("fieldset", "segmented", make("legend", "", legend));
  const inputs: HTMLInputElement[] = [];
  for (const option of options) {
    const input = make("input", "");
    input.type = "checkbox";
    input.id = `${name}-${option}`;
    input.value = option;
    input.checked = on.includes(option);
    const label = make("label", "", option);
    label.htmlFor = input.id;
    group.append(input, label);
    inputs.push(input);
  }
  return { group, chosen: () => inputs.filter((input) => input.checked).map((input) => input.value) };
}

/** The form registering a client; `registered` redraws the view with the outcome. */
function registerForm(screen: Screen, registered: (message: string) => void): HTMLFormElement {
  const keyFor = keys();
  const id = make("input", "mono");
  id.type = "text";
  id.autocomplete = "off";
  id.spellcheck = false;
  const kind = segmented("Kind", "client-kind", ["public", "confidential"], "public");
  const algorithm = segmented("Signs with", "client-alg", ALGORITHMS, ALGORITHMS[0]);
  const jwk = area("client-jwk", "Public key (JWK)");
  // Only a confidential client signs, so the signing fields show only for one.
  const signing = [algorithm.group, jwk.row];
  for (const part of signing) {
    part.hidden = true;
  }
  kind.group.addEventListener("change", () => {
    for (const part of signing) {
      part.hidden = kind.chosen() !== "confidential";
    }
  });
  const redirects = area("client-redirects", "Redirect URIs, one per line (exact, https or loopback)");
  const scopes = make("input", "mono");
  scopes.type = "text";
  scopes.autocomplete = "off";
  scopes.spellcheck = false;
  const resources = area("client-resources", "Resources its tokens may go to, one per line (optional)");
  const grants = toggles("Grants", "client-grant", GRANTS, ["authorization_code"]);
  const dpop = toggles("Token binding", "client-dpop", ["DPoP-bound tokens"], []);
  const reason = reasonField("client-reason");
  const said = notice();
  const submit = make("button", "primary", "Register the client");
  submit.type = "submit";
  const fields: Record<FormField, HTMLElement> = {
    id,
    jwk: jwk.input,
    algorithm: algorithm.group,
    redirects: redirects.input,
    scopes,
    grants: grants.group,
  };
  const form = make(
    "form",
    "change-form",
    make("h2", "", "Register a client"),
    labelled("client-id", "Client id", id),
    kind.group,
    ...signing,
    redirects.row,
    labelled("client-scopes", "Scopes it may ask for, separated by spaces", scopes),
    resources.row,
    grants.group,
    dpop.group,
    reason.row,
    said,
    submit,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    said.hidden = true;
    for (const element of Object.values(fields)) {
      element.removeAttribute("aria-invalid");
    }
    const made = registrationOf({
      id: id.value,
      confidential: kind.chosen() === "confidential",
      algorithm: algorithm.chosen() ?? "",
      jwk: jwk.input.value,
      redirects: redirects.input.value,
      scopes: scopes.value,
      resources: resources.input.value,
      grants: grants.chosen(),
      dpop: dpop.chosen().length > 0,
    });
    if ("wrong" in made) {
      said.textContent = WRONG[made.wrong];
      said.hidden = false;
      fields[made.wrong].setAttribute("aria-invalid", "true");
      fields[made.wrong].focus();
      return;
    }
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    submit.disabled = true;
    void change("api/clients", keyFor, { ...made.body, reason: why }).then((answer) => {
      submit.disabled = false;
      if (!screen.live()) {
        return;
      }
      const client = answer.ok ? readRegistered(answer.body) : null;
      if (client !== null) {
        registered(`Client ${client.id} registered as a ${client.kind} client.`);
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "That client", clientRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  return form;
}

/** A list of values as code, one per line, or a dash when there are none. */
function values(list: readonly string[]): Node {
  if (list.length === 0) {
    return document.createTextNode("-");
  }
  const cell = make("ul", "plain");
  for (const value of list) {
    cell.append(make("li", "", make("code", "", value)));
  }
  return cell;
}

/** The registrations as a table. */
function clientsTable(clients: readonly Client[]): HTMLTableElement {
  const head = make(
    "tr",
    "",
    make("th", "", "Client"),
    make("th", "", "Kind"),
    make("th", "", "Redirect URIs"),
    make("th", "", "Scopes"),
    make("th", "", "Grants"),
  );
  for (const cell of head.children) {
    cell.setAttribute("scope", "col");
  }
  const body = make("tbody", "");
  for (const client of clients) {
    const kind = make("span", "badge", client.kind);
    const name = make("td", "", make("code", "", client.id));
    if (client.console) {
      name.append(make("div", "", make("span", "pill", "this console")));
    }
    const signs = client.assertionAlg === null ? kind : make("span", "", kind, ` ${client.assertionAlg}`);
    body.append(
      make(
        "tr",
        "",
        name,
        make("td", "", signs),
        make("td", "", values(client.redirectUris)),
        make("td", "", values(client.scopeCeiling)),
        make("td", "", values(client.grantTypes)),
      ),
    );
  }
  return make("table", "grid", make("thead", "", head), body);
}

/** The clients view after `after`, with `message` said once it is drawn. */
export async function clientsView(screen: Screen, after: string | null, message = ""): Promise<void> {
  say("Loading the clients.");
  const answer = await call("GET", clientsPath(after));
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Clients", answer, "That page");
    return;
  }
  const page = readClientsPage(answer.body);
  if (page === null) {
    unreadable(screen, "Clients");
    return;
  }
  const redraw = (said: string): void => void clientsView(screen, after, said);
  const parts: Node[] = [
    heading("Clients"),
    make("p", "lead", "Applications that sign people in through this company. A public client always uses PKCE; a "
      + "confidential one proves itself with a key it registered. No shared secrets."),
  ];
  parts.push(
    page.clients.length === 0
      ? make("p", "empty", after === null ? "No clients yet." : "No more clients.")
      : clientsTable(page.clients),
  );
  const paging = make("p", "paging");
  if (after !== null) {
    paging.append(link("#/clients", "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`#/clients?${new URLSearchParams({ after: page.next }).toString()}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  parts.push(registerForm(screen, redraw));
  show(screen.view, ...parts);
  say(message);
}
