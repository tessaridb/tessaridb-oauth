"use strict";
(() => {
  // src/flow.ts
  function field(value, key) {
    if (typeof value !== "object" || value === null) {
      return void 0;
    }
    const fields = Object.entries(value);
    return fields.find(([name]) => name === key)?.[1];
  }
  function strings(value) {
    return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : null;
  }

  // src/console-read.ts
  var ROLES = ["users", "clients", "policy", "audit", "companies"];
  var NEEDS = [
    ["users", "users"],
    ["clients", "clients"],
    ["operators", null],
    ["policy", "policy"],
    ["audit", "audit"],
    ["companies", "companies"]
  ];
  function isRole(name) {
    return ROLES.some((role) => role === name);
  }
  function readMe(body) {
    const user = field(body, "user");
    const roles = strings(field(body, "roles"));
    if (typeof user !== "string" || user === "" || roles === null) {
      return null;
    }
    return { user, roles: roles.filter(isRole) };
  }
  function offered(roles) {
    return NEEDS.filter(([, need]) => need === null || roles.includes(need)).map(([section]) => section);
  }
  function route(hash) {
    const [path = "", search = ""] = hash.replace(/^#/, "").split("?", 2);
    const query = new URLSearchParams(search);
    const parts = path.split("/").filter((part) => part !== "");
    const [section, id] = parts;
    if (section === "users" && id !== void 0 && parts.length === 2) {
      return { kind: "user", id: decodeURIComponent(id) };
    }
    switch (parts.length === 1 ? section : void 0) {
      case "users":
        return { kind: "users", email: query.get("email"), after: query.get("after") };
      case "clients":
        return { kind: "clients", after: query.get("after") };
      case "operators":
        return { kind: "operators", after: query.get("after") };
      case "policy":
        return { kind: "policy" };
      case "audit": {
        const after = query.get("after");
        return { kind: "audit", after: after !== null && /^\d+$/.test(after) ? Number(after) : null };
      }
      case "companies":
        return { kind: "companies", after: query.get("after") };
      default:
        return { kind: "overview" };
    }
  }
  function readRefusal(status, body, retryAfter) {
    const code = field(body, "code");
    if (status === 401) {
      return { kind: "signed_out" };
    }
    if (status === 403 && code === "role_required") {
      return { kind: "role" };
    }
    if (status === 404) {
      return { kind: "not_found" };
    }
    if (status === 429) {
      const seconds2 = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      return { kind: "throttled", seconds: seconds2 };
    }
    if ((status === 400 || status === 403 || status === 409) && typeof code === "string") {
      return { kind: "refused", code };
    }
    return { kind: "failed" };
  }
  function confirmedBy(typed, company2) {
    return typed.trim() === company2 && company2 !== "";
  }

  // src/console-dom.ts
  function make(tag, className, ...children) {
    const made = document.createElement(tag);
    if (className !== "") {
      made.className = className;
    }
    made.append(...children);
    return made;
  }
  function link(href, text, className = "") {
    const made = make("a", className, text);
    made.href = href;
    return made;
  }
  function button(text, className, then) {
    const made = make("button", className, text);
    made.type = "button";
    made.addEventListener("click", then);
    return made;
  }
  function heading(text) {
    const made = make("h1", "view-title", text);
    made.tabIndex = -1;
    return made;
  }
  function show(view2, ...children) {
    view2.replaceChildren(...children);
    view2.querySelector(".view-title")?.focus();
  }
  function labelled(id, text, input) {
    const label2 = make("label", "", text);
    label2.htmlFor = id;
    input.id = id;
    return make("div", "field", label2, input);
  }
  function segmented(legend, name, options, checked) {
    const group = make("fieldset", "segmented", make("legend", "", legend));
    const inputs = [];
    for (const option of options) {
      const input = make("input", "");
      input.type = "radio";
      input.name = name;
      input.id = `${name}-${option}`;
      input.value = option;
      input.checked = option === checked;
      const label2 = make("label", "", option);
      label2.htmlFor = input.id;
      group.append(input, label2);
      inputs.push([input, option]);
    }
    return { group, chosen: () => inputs.find(([input]) => input.checked)?.[1] ?? null };
  }

  // src/dom.ts
  function element(id, kind) {
    const found = document.getElementById(id);
    if (!(found instanceof kind)) {
      throw new Error(`the page has no ${kind.name} #${id}`);
    }
    return found;
  }
  async function call(method, path, body, extra) {
    const init = {
      method,
      credentials: "same-origin",
      cache: "no-store",
      headers: { accept: "application/json", "content-type": "application/json", ...extra }
    };
    if (body !== void 0) {
      init.body = JSON.stringify(body);
    }
    try {
      const response = await fetch(path, init);
      const text = await response.text();
      let parsed = null;
      try {
        parsed = text === "" ? null : JSON.parse(text);
      } catch {
        parsed = null;
      }
      return { ok: response.ok, status: response.status, body: parsed, retryAfter: response.headers.get("retry-after") };
    } catch {
      return { ok: false, status: 0, body: null, retryAfter: null };
    }
  }
  function say(text) {
    element("status", HTMLParagraphElement).textContent = text;
  }

  // src/console-copy.ts
  function refusalText(refusal, what) {
    switch (refusal.kind) {
      case "signed_out":
        return "Your console session has ended. Sign in again.";
      case "role":
        return "Your operator roles do not include this. Ask an operator who holds the role to grant it.";
      case "not_found":
        return `${what} was not found in this company.`;
      case "throttled":
        return refusal.seconds === null ? "Too many requests from here. Wait a moment and try again." : `Too many requests from here. Try again in ${refusal.seconds} seconds.`;
      case "refused":
        return `The server refused this (${refusal.code}).`;
      case "failed":
        return "The server did not answer. Try again.";
    }
  }
  function changeRefusalText(code) {
    switch (code) {
      case "email_taken":
        return "An account in this company already signs in with this address. Look it up instead.";
      case "already_enrolled":
        return "This account has already set a password, so it needs no enrolment code.";
      case "account_disabled":
        return "This account is disabled. Enable it before issuing an enrolment code.";
      case "changed_meanwhile":
        return "Someone changed this while you were looking. The view now shows it as it is; check it and try again.";
      case "reason_required":
        return "Say why, in 1 to 500 characters.";
      case "idempotency_key_reused":
        return "This form was already used for a different change. Reload the view and try again.";
      case "change_in_progress":
        return "This change is still being made. Wait a moment, then reload the view.";
      case "cross_origin":
        return "The request did not come from this console. Reload the console and try again.";
      default:
        return "The server refused this change. Reload the view and try again.";
    }
  }
  function operatorRefusalText(code) {
    switch (code) {
      case "self_grant":
        return "No operator grants a role to themselves. Ask another operator who holds the role.";
      case "above_ceiling":
        return "Accounts of this company may not hold this role.";
      case "account_disabled":
        return "This account is disabled. Enable it before granting it a role.";
      case "not_granted":
        return "This account does not hold this role any more. Reload the view to see the current grants.";
      default:
        return changeRefusalText(code);
    }
  }
  function clientRefusalText(code) {
    switch (code) {
      case "client_taken":
        return "This company already has a client with this id. Choose another id.";
      case "client_reserved":
        return "This id belongs to the console's own client, which the server manages. Choose another id.";
      default:
        return changeRefusalText(code);
    }
  }
  function clientRemovalRefusalText(code) {
    return code === "client_reserved" ? "The console's own client is managed by the server and is not removed." : changeRefusalText(code);
  }
  function companyRefusalText(code) {
    switch (code) {
      case "company_taken":
        return "A company with this id already exists. Choose another id.";
      case "system_company":
        return "The system company runs this console and is never suspended.";
      case "changed_meanwhile":
        return "This company is no longer in the state the view showed. Reload the view and try again.";
      default:
        return changeRefusalText(code);
    }
  }

  // src/users-change.ts
  var REASON_MAX_CHARS = 500;
  function reasonOf(typed) {
    const reason = typed.trim();
    const length = [...reason].length;
    return length >= 1 && length <= REASON_MAX_CHARS ? reason : null;
  }
  function count(body, key) {
    const value = field(body, key);
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function readOpened(body) {
    const user = field(body, "user");
    const email = field(body, "email");
    return typeof user === "string" && user !== "" && typeof email === "string" ? { user, email } : null;
  }
  function readDisabled(body) {
    const sessions = count(body, "sessions");
    const families = count(body, "families");
    const accessTokensEndBy = count(body, "access_tokens_end_by");
    if (sessions === null || families === null || accessTokensEndBy === null) {
      return null;
    }
    return { sessions, families, accessTokensEndBy };
  }
  function readRevealed(body) {
    const email = field(body, "email");
    return typeof email === "string" && email !== "" ? { email } : null;
  }
  function readIssued(body) {
    const code = field(body, "code");
    const validSecs = count(body, "valid_secs");
    if (field(body, "shown_once") !== true || typeof code !== "string" || code === "" || validSecs === null) {
      return null;
    }
    return { code, validHours: Math.floor(validSecs / 3600) };
  }
  function keyring(fresh) {
    let last = null;
    return (body) => {
      const sent = JSON.stringify(body);
      if (last === null || last.sent !== sent) {
        last = { sent, key: fresh() };
      }
      return last.key;
    };
  }

  // src/console-change.ts
  function keys() {
    return keyring(() => crypto.randomUUID());
  }
  function change(path, keyFor, body, method = "POST") {
    return call(method, path, body, { "idempotency-key": keyFor({ ...body, "@path": path }) });
  }
  function refusedText(screen, answer, what, words = changeRefusalText) {
    const refusal = readRefusal(answer.status, answer.body, answer.retryAfter);
    if (refusal.kind === "signed_out") {
      screen.signedOut();
      return null;
    }
    return refusal.kind === "refused" ? words(refusal.code) : refusalText(refusal, what);
  }
  function reasonField(id) {
    const input = make("input", "");
    input.type = "text";
    input.required = true;
    input.maxLength = 500;
    input.autocomplete = "off";
    return { input, row: labelled(id, "Reason (recorded with the change)", input) };
  }
  function reasonIn(input, notice2) {
    const reason = reasonOf(input.value);
    if (reason === null) {
      notice2.textContent = changeRefusalText("reason_required");
      notice2.hidden = false;
      input.setAttribute("aria-invalid", "true");
      input.focus();
      return null;
    }
    input.removeAttribute("aria-invalid");
    return reason;
  }
  function notice() {
    const made = make("p", "notice");
    made.setAttribute("role", "alert");
    made.hidden = true;
    return made;
  }
  function refusedOn(screen, title, answer, what) {
    const refusal = readRefusal(answer.status, answer.body, answer.retryAfter);
    if (refusal.kind === "signed_out") {
      screen.signedOut();
      return;
    }
    show(screen.view, heading(title), make("p", "notice", refusalText(refusal, what)));
    say("");
  }
  function unreadable(screen, title) {
    show(screen.view, heading(title), make("p", "notice", "The server answered in a shape the console cannot read."));
    say("");
  }

  // src/audit-read.ts
  var FIELDS = [
    ["client_id", "Client", "text"],
    ["scopes", "Scopes", "scopes"],
    ["user", "Account", "text"],
    ["families", "Refresh families", "count"],
    ["subject", "Subject", "text"],
    ["audience", "Audience", "text"],
    ["jti", "Token id", "text"],
    ["auth_method", "Client authentication", "text"],
    ["bound_to", "Bound to key", "text"],
    ["reason", "Reason", "text"],
    ["actor", "Operator", "text"],
    ["role", "Role", "text"],
    ["action", "Action", "text"]
  ];
  function auditPath(after) {
    return after === null ? "api/audit" : `api/audit?after=${after}`;
  }
  function natural(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function readEvent(value) {
    const position = natural(field(value, "position"));
    const at = natural(field(value, "at"));
    const kind = field(value, "kind");
    if (position === null || at === null || typeof kind !== "string") {
      return null;
    }
    const details = [];
    for (const [key, label2, shape] of FIELDS) {
      const raw = field(value, key);
      if (raw === void 0) {
        continue;
      }
      const text = shown(raw, shape);
      if (text === null) {
        return null;
      }
      details.push([label2, text]);
    }
    return { position, at, kind, details };
  }
  function shown(raw, shape) {
    switch (shape) {
      case "text":
        return typeof raw === "string" ? raw : null;
      case "scopes":
        return Array.isArray(raw) && raw.every((scope) => typeof scope === "string") ? raw.join(" ") : null;
      case "count": {
        const count3 = natural(raw);
        return count3 === null ? null : String(count3);
      }
    }
  }
  function readAuditPage(body) {
    const listed = field(body, "events");
    const next = field(body, "next");
    if (!Array.isArray(listed) || next !== null && natural(next) === null) {
      return null;
    }
    const events = [];
    for (const value of listed) {
      const event = readEvent(value);
      if (event === null) {
        return null;
      }
      events.push(event);
    }
    return { events, next: next === null ? null : natural(next) };
  }

  // src/audit.ts
  function moment(seconds2) {
    return new Intl.DateTimeFormat(void 0, { dateStyle: "medium", timeStyle: "medium" }).format(
      new Date(seconds2 * 1e3)
    );
  }
  function row(event) {
    const details = make("dl", "facts");
    for (const [label2, value] of event.details) {
      details.append(make("dt", "", label2), make("dd", "", make("code", "", value)));
    }
    return make(
      "tr",
      "",
      make("td", "", make("code", "", String(event.position))),
      make("td", "", moment(event.at)),
      make("td", "", make("code", "", event.kind)),
      make("td", "", event.details.length > 0 ? details : "")
    );
  }
  async function auditView(screen, after) {
    say("Loading the audit trail.");
    const answer = await call("GET", auditPath(after));
    if (!screen.live()) {
      return;
    }
    if (!answer.ok) {
      refusedOn(screen, "Audit trail", answer, "That page");
      return;
    }
    const page = readAuditPage(answer.body);
    if (page === null) {
      unreadable(screen, "Audit trail");
      return;
    }
    const parts = [
      heading("Audit trail"),
      make("p", "lead", "What was done in this company, oldest first, with the fields each event was recorded with.")
    ];
    if (page.events.length === 0) {
      parts.push(make("p", "empty", after === null ? "Nothing has been recorded yet." : "No later events."));
    } else {
      const head = make(
        "tr",
        "",
        make("th", "", "Position"),
        make("th", "", "When"),
        make("th", "", "Event"),
        make("th", "", "Details")
      );
      for (const cell of head.children) {
        cell.setAttribute("scope", "col");
      }
      parts.push(make("table", "grid", make("thead", "", head), make("tbody", "", ...page.events.map(row))));
    }
    const paging = make("p", "paging");
    if (after !== null) {
      paging.append(link("#/audit", "First page"));
    }
    if (page.next !== null) {
      paging.append(link(`#/audit?after=${page.next}`, "Next page"));
    }
    if (paging.childElementCount > 0) {
      parts.push(paging);
    }
    show(screen.view, ...parts);
    say("");
  }

  // src/companies-read.ts
  var ID_MAX_BYTES = 63;
  var NAME_MAX_CHARS = 100;
  var STATUSES = ["provisioning", "active", "suspended"];
  function isStatus(name) {
    return STATUSES.some((status) => status === name);
  }
  function companiesPath(after) {
    return after === null ? "api/companies" : `api/companies?${new URLSearchParams({ after }).toString()}`;
  }
  function readCompany(value) {
    const id = field(value, "id");
    const name = field(value, "name");
    const status = field(value, "status");
    const createdAt = field(value, "created_at");
    const createdBy = field(value, "created_by");
    if (typeof id !== "string" || id === "" || typeof name !== "string" || !isStatus(status) || typeof createdAt !== "number" || !Number.isSafeInteger(createdAt) || createdAt < 0 || typeof createdBy !== "string") {
      return null;
    }
    return { id, name, status, createdAt, createdBy };
  }
  function readCompaniesPage(body) {
    const listed = field(body, "companies");
    const next = field(body, "next");
    if (!Array.isArray(listed) || next !== null && typeof next !== "string") {
      return null;
    }
    const companies = [];
    for (const value of listed) {
      const company2 = readCompany(value);
      if (company2 === null) {
        return null;
      }
      companies.push(company2);
    }
    return { companies, next };
  }
  function companyIdOf(typed) {
    const id = typed.trim();
    return id.length <= ID_MAX_BYTES && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(id) ? id : null;
  }
  function companyNameOf(typed) {
    const name = typed.trim();
    const length = [...name].length;
    return length >= 1 && length <= NAME_MAX_CHARS && !/\p{Cc}/u.test(name) ? name : null;
  }

  // src/companies.ts
  function statusBadge(company2) {
    const badge2 = make("span", "badge", company2.status);
    badge2.dataset["state"] = company2.status === "active" ? "ok" : "warn";
    return badge2;
  }
  function day(seconds2) {
    return new Intl.DateTimeFormat(void 0, { dateStyle: "medium" }).format(new Date(seconds2 * 1e3));
  }
  function createForm(screen, created) {
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
      submit
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      said.hidden = true;
      const chosen = companyIdOf(id.value);
      const named = companyNameOf(name.value);
      if (chosen === null || named === null) {
        const wrong = chosen === null ? id : name;
        said.textContent = chosen === null ? "Give an id of 1 to 63 lowercase letters, digits and inner hyphens." : "Give a name of 1 to 100 characters.";
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
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "That company", companyRefusalText);
        if (text !== null) {
          said.textContent = text;
          said.hidden = false;
        }
      });
    });
    return form;
  }
  function directory(screen, own, companies, moved) {
    const keyFor = keys();
    const reason = reasonField("move-reason");
    const said = notice();
    const question = make("p", "");
    const typed = make("input", "mono");
    typed.type = "text";
    typed.autocomplete = "off";
    typed.spellcheck = false;
    const typedRow = labelled("move-company", "Type the company id to confirm", typed);
    let target = null;
    const go = make("button", "danger", "");
    go.type = "button";
    const confirmPanel = make("div", "confirm", question, typedRow, reason.row, said);
    confirmPanel.hidden = true;
    const ask = (company2) => {
      target = company2;
      const suspending = company2.status === "active";
      question.replaceChildren(
        suspending ? "Suspend " : "Resume ",
        make("code", "", company2.id),
        suspending ? "? Its sign-in, its tokens and its console stop being served, so no application can sign anyone in through it until it is resumed." : "? Its sign-in, tokens and console are served again."
      );
      typedRow.hidden = !suspending;
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
      make("th", "", "Change")
    );
    for (const cell of head.children) {
      cell.setAttribute("scope", "col");
    }
    const body = make("tbody", "");
    for (const company2 of companies) {
      const offered2 = company2.id !== own && (company2.status === "active" || company2.status === "suspended");
      const action = offered2 ? button(company2.status === "active" ? "Suspend" : "Resume", "quiet", () => ask(company2)) : "";
      body.append(
        make(
          "tr",
          "",
          make("td", "", make("code", "", company2.id)),
          make("td", "", company2.name),
          make("td", "", statusBadge(company2)),
          make("td", "", day(company2.createdAt)),
          make("td", "", make("code", "", company2.createdBy)),
          make("td", "", action)
        )
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
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "That company", companyRefusalText);
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
  async function companiesView(screen, own, after, message = "") {
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
    const redraw = (said) => void companiesView(screen, own, after, said);
    const parts = [
      heading("Companies"),
      make("p", "lead", "Every company this node serves, each its own issuer with its own users, clients and keys.")
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

  // src/clients-read.ts
  var ALGORITHMS = ["EdDSA", "ES256"];
  var GRANTS = ["authorization_code", "refresh_token", "client_credentials"];
  function clientsPath(after) {
    return after === null ? "api/clients" : `api/clients?${new URLSearchParams({ after }).toString()}`;
  }
  function readClient(value) {
    const id = field(value, "client_id");
    const kind = field(value, "kind");
    const authMethod = field(value, "auth_method");
    const assertionAlg = field(value, "assertion_alg");
    const redirectUris = strings(field(value, "redirect_uris"));
    const scopeCeiling = strings(field(value, "scope_ceiling"));
    const resources = strings(field(value, "resources"));
    const grantTypes = strings(field(value, "grant_types"));
    const dpop = field(value, "dpop_bound_access_tokens");
    const keys2 = field(value, "keys");
    const console = field(value, "console");
    if (typeof id !== "string" || id === "" || kind !== "public" && kind !== "confidential" || typeof authMethod !== "string" || assertionAlg !== null && typeof assertionAlg !== "string" || redirectUris === null || scopeCeiling === null || resources === null || grantTypes === null || typeof dpop !== "boolean" || typeof keys2 !== "number" || !Number.isSafeInteger(keys2) || keys2 < 0 || typeof console !== "boolean") {
      return null;
    }
    return { id, kind, authMethod, assertionAlg, redirectUris, scopeCeiling, resources, grantTypes, dpop, keys: keys2, console };
  }
  function readClientsPage(body) {
    const listed = field(body, "clients");
    const next = field(body, "next");
    if (!Array.isArray(listed) || next !== null && typeof next !== "string") {
      return null;
    }
    const clients = [];
    for (const value of listed) {
      const client = readClient(value);
      if (client === null) {
        return null;
      }
      clients.push(client);
    }
    return { clients, next };
  }
  function readRegistered(body) {
    return readClient(body);
  }
  function clientPath(id) {
    return `api/clients/${encodeURIComponent(id)}`;
  }
  function removalPath(id) {
    return `${clientPath(id)}/remove`;
  }
  function count2(body, key) {
    const value = field(body, key);
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function readHolders(body) {
    return count2(body, "holders");
  }
  function readRemoved(body) {
    const clientId = field(body, "client_id");
    const consents = count2(body, "consents");
    const families = count2(body, "families");
    const accessTokensEndBy = count2(body, "access_tokens_end_by");
    if (typeof clientId !== "string" || clientId === "" || consents === null || families === null || accessTokensEndBy === null) {
      return null;
    }
    return { clientId, consents, families, accessTokensEndBy };
  }
  function listOf(text) {
    return text.split(/\s+/).filter((value) => value !== "");
  }
  function clientIdOf(id) {
    return id.length >= 1 && id.length <= 255 && /^[\x20-\x7e]+$/.test(id);
  }
  function jwkOf(text) {
    try {
      const parsed = JSON.parse(text);
      return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  function registrationOf(form) {
    const id = form.id.trim();
    if (!clientIdOf(id)) {
      return { wrong: "id" };
    }
    const redirects = listOf(form.redirects);
    const grants = GRANTS.filter((grant) => form.grants.includes(grant));
    if (grants.length === 0 || !form.confidential && grants.includes("client_credentials")) {
      return { wrong: "grants" };
    }
    if (grants.includes("authorization_code") && redirects.length === 0) {
      return { wrong: "redirects" };
    }
    const shared = {
      client_id: id,
      redirect_uris: redirects,
      scope_ceiling: listOf(form.scopes),
      resources: listOf(form.resources)
    };
    if (!form.confidential) {
      return {
        body: { ...shared, auth_method: "none", grant_types: grants, dpop_bound_access_tokens: form.dpop }
      };
    }
    const jwk = jwkOf(form.jwk.trim());
    if (jwk === null) {
      return { wrong: "jwk" };
    }
    if (!ALGORITHMS.some((algorithm) => algorithm === form.algorithm)) {
      return { wrong: "algorithm" };
    }
    return {
      body: {
        ...shared,
        auth_method: "private_key_jwt",
        assertion_alg: form.algorithm,
        jwks: [jwk],
        grant_types: grants,
        dpop_bound_access_tokens: form.dpop
      }
    };
  }

  // src/clients-remove.ts
  async function removalPanel(screen, client, host, redraw) {
    say(`Reading who holds a grant to ${client.id}.`);
    const read = await call("GET", clientPath(client.id));
    if (!screen.live()) {
      return;
    }
    const holders = read.ok ? readHolders(read.body) : null;
    if (holders === null) {
      const text = read.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, read, "That client", clientRemovalRefusalText);
      if (text !== null) {
        say(text);
      }
      return;
    }
    const keyFor = keys();
    const typed = make("input", "mono");
    typed.type = "text";
    typed.autocomplete = "off";
    typed.spellcheck = false;
    const reason = reasonField("remove-reason");
    const said = notice();
    const remove = button("Remove the client", "danger", () => {
      if (!confirmedBy(typed.value, client.id)) {
        return;
      }
      const why = reasonIn(reason.input, said);
      if (why === null) {
        return;
      }
      remove.disabled = true;
      void change(removalPath(client.id), keyFor, { reason: why }).then((answer) => {
        remove.disabled = false;
        if (!screen.live()) {
          return;
        }
        const removed = answer.ok ? readRemoved(answer.body) : null;
        if (removed !== null) {
          const until = new Date(removed.accessTokensEndBy * 1e3).toLocaleTimeString();
          redraw(
            `Client ${removed.clientId} removed: ${removed.consents} grants and ${removed.families} refresh families ended; access tokens it already holds stop working by ${until}.`
          );
          return;
        }
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "That client", clientRemovalRefusalText);
        if (text !== null) {
          said.textContent = text;
          said.hidden = false;
        }
      });
    });
    remove.disabled = true;
    typed.addEventListener("input", () => {
      remove.disabled = !confirmedBy(typed.value, client.id);
    });
    const keep = button("Keep it", "secondary", () => {
      host.replaceChildren();
      say(`${client.id} kept.`);
    });
    const users = holders === 1 ? "1 user holds" : `${holders} users hold`;
    host.replaceChildren(
      make(
        "section",
        "change-form confirm",
        make("h2", "", "Remove ", make("code", "", client.id), "?"),
        make(
          "p",
          "",
          `${users} a grant to it. Removing it deletes the registration, revokes those grants and every refresh token it holds; access tokens it already has stop working within five minutes. This cannot be undone.`
        ),
        labelled("remove-typed", "Type the client id to confirm", typed),
        reason.row,
        said,
        make("div", "actions", remove, keep)
      )
    );
    typed.focus();
    say(`Confirm removing ${client.id}.`);
  }

  // src/clients.ts
  var WRONG = {
    id: "Give an id of 1 to 255 visible characters.",
    jwk: "Paste the client's public key as one JSON object (a JWK).",
    algorithm: "Choose the algorithm the client signs with.",
    redirects: "A client using the code flow needs at least one redirect URI.",
    scopes: "Give the scopes as words separated by spaces.",
    grants: "Choose at least one grant; only a confidential client may act as itself."
  };
  function area(id, text) {
    const input = make("textarea", "mono");
    input.id = id;
    input.rows = 2;
    input.spellcheck = false;
    const label2 = make("label", "", text);
    label2.htmlFor = id;
    return { input, row: make("div", "field", label2, input) };
  }
  function toggles(legend, name, options, on) {
    const group = make("fieldset", "segmented", make("legend", "", legend));
    const inputs = [];
    for (const option of options) {
      const input = make("input", "");
      input.type = "checkbox";
      input.id = `${name}-${option}`;
      input.value = option;
      input.checked = on.includes(option);
      const label2 = make("label", "", option);
      label2.htmlFor = input.id;
      group.append(input, label2);
      inputs.push(input);
    }
    return { group, chosen: () => inputs.filter((input) => input.checked).map((input) => input.value) };
  }
  function registerForm(screen, registered) {
    const keyFor = keys();
    const id = make("input", "mono");
    id.type = "text";
    id.autocomplete = "off";
    id.spellcheck = false;
    const kind = segmented("Kind", "client-kind", ["public", "confidential"], "public");
    const algorithm = segmented("Signs with", "client-alg", ALGORITHMS, ALGORITHMS[0]);
    const jwk = area("client-jwk", "Public key (JWK)");
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
    const fields = {
      id,
      jwk: jwk.input,
      algorithm: algorithm.group,
      redirects: redirects.input,
      scopes,
      grants: grants.group
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
      submit
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      said.hidden = true;
      for (const element2 of Object.values(fields)) {
        element2.removeAttribute("aria-invalid");
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
        dpop: dpop.chosen().length > 0
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
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "That client", clientRefusalText);
        if (text !== null) {
          said.textContent = text;
          said.hidden = false;
        }
      });
    });
    return form;
  }
  function values(list) {
    if (list.length === 0) {
      return document.createTextNode("-");
    }
    const cell = make("ul", "plain");
    for (const value of list) {
      cell.append(make("li", "", make("code", "", value)));
    }
    return cell;
  }
  function clientsTable(clients, remove) {
    const head = make(
      "tr",
      "",
      make("th", "", "Client"),
      make("th", "", "Kind"),
      make("th", "", "Redirect URIs"),
      make("th", "", "Scopes"),
      make("th", "", "Grants"),
      make("th", "", "Actions")
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
          make("td", "", client.console ? "" : removeButton(client, remove))
        )
      );
    }
    return make("table", "grid", make("thead", "", head), body);
  }
  function removeButton(client, remove) {
    const pressed = button("Remove", "secondary", () => remove(client));
    pressed.setAttribute("aria-label", `Remove ${client.id}`);
    return pressed;
  }
  async function clientsView(screen, after, message = "") {
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
    const redraw = (said) => void clientsView(screen, after, said);
    const parts = [
      heading("Clients"),
      make("p", "lead", "Applications that sign people in through this company. A public client always uses PKCE; a confidential one proves itself with a key it registered. No shared secrets.")
    ];
    const removal = make("div", "");
    const remove = (client) => void removalPanel(screen, client, removal, redraw);
    parts.push(
      page.clients.length === 0 ? make("p", "empty", after === null ? "No clients yet." : "No more clients.") : clientsTable(page.clients, remove),
      removal
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

  // src/operators-read.ts
  var DEFAULT_DAYS = 90;
  var MAX_DAYS = 365;
  function operatorsPath(after) {
    return after === null ? "api/operators" : `api/operators?${new URLSearchParams({ after }).toString()}`;
  }
  function seconds(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  function readGrant(value) {
    const user = field(value, "user");
    const role = field(value, "role");
    const grantedBy = field(value, "granted_by");
    const grantedAt = seconds(field(value, "granted_at"));
    const expires = field(value, "expires_at");
    const expiresAt = expires === null ? null : seconds(expires);
    const reason = field(value, "reason");
    if (typeof user !== "string" || user === "" || typeof role !== "string" || !isRole(role) || typeof grantedBy !== "string" || grantedAt === null || expires !== null && expiresAt === null || typeof reason !== "string") {
      return null;
    }
    return { user, role, grantedBy, grantedAt, expiresAt, reason };
  }
  function readGrantsPage(body) {
    const listed = field(body, "operators");
    const next = field(body, "next");
    if (!Array.isArray(listed) || next !== null && typeof next !== "string") {
      return null;
    }
    const grants = [];
    for (const value of listed) {
      const grant = readGrant(value);
      if (grant === null) {
        return null;
      }
      grants.push(grant);
    }
    return { grants, next };
  }
  function readRevoked(body) {
    const user = field(body, "user");
    const role = field(body, "role");
    return field(body, "revoked") === true && typeof user === "string" && typeof role === "string" ? { user, role } : null;
  }
  function daysOf(typed) {
    const text = typed.trim();
    if (text === "") {
      return DEFAULT_DAYS;
    }
    if (!/^\d{1,3}$/.test(text)) {
      return null;
    }
    const days = Number(text);
    return days >= 1 && days <= MAX_DAYS ? days : null;
  }

  // src/operators.ts
  var DAYS_WRONG = "Give a whole number of days from 1 to 365, or leave it empty for 90.";
  function day2(seconds2) {
    return new Intl.DateTimeFormat(void 0, { dateStyle: "medium" }).format(new Date(seconds2 * 1e3));
  }
  function grantForm(screen, roles, granted) {
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
    const picker = segmented("Role", "grant-role", roles, roles[0] ?? null);
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
      submit
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
  function grantsTable(screen, grants, revoked) {
    const keyFor = keys();
    const reason = reasonField("revoke-reason");
    const said = notice();
    const question = make("p", "");
    let target = null;
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
      make("th", "", "Change")
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
          "? Their console stops offering what the role allows at once; another grant restores it."
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
          make("td", "", grant.expiresAt === null ? "Never" : day2(grant.expiresAt)),
          make("td", "", grant.reason),
          make("td", "", revoke)
        )
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
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "That grant", operatorRefusalText);
        if (text !== null) {
          said.textContent = text;
          said.hidden = false;
        }
      });
    });
    confirmPanel.append(make("div", "actions", confirm, keep));
    return [make("table", "grid", make("thead", "", head), body), confirmPanel];
  }
  async function operatorsView(screen, who, after, message = "") {
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
    const redraw = (said) => void operatorsView(screen, who, after, said);
    const parts = [
      heading("Operators"),
      make("p", "lead", "Current grants of the roles you hold. Every grant expires; nobody grants a role to themselves.")
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
      who.roles.length > 0 ? grantForm(screen, who.roles, redraw) : make("p", "muted", "You hold no roles, so you can grant none.")
    );
    show(screen.view, ...parts);
    say(message);
  }

  // src/policy-read.ts
  var POLICIES = ["off", "optional", "required"];
  function isPolicy(name) {
    return POLICIES.some((policy) => policy === name);
  }
  function readPolicy(body) {
    const policy = field(body, "policy");
    return isPolicy(policy) ? policy : null;
  }
  function policyConsequence(from, to) {
    if (from === to) {
      return null;
    }
    switch (to) {
      case "required":
        return "Every account of this company must hold a second factor. Accounts without one enrol it at their next sign-in before they can continue.";
      case "optional":
        return from === "required" ? "Accounts may stop using a second factor; those that keep one still sign in with it." : "Accounts may add a second factor and then sign in with it; nobody is made to.";
      case "off":
        return "No account of this company is asked for a second factor: a password alone signs in, including for accounts that enrolled one.";
    }
  }

  // src/policy.ts
  var PATH = "api/policy/two-factor";
  function badge(policy) {
    const made = make("span", "badge", policy);
    made.dataset["state"] = policy === "off" ? "warn" : "ok";
    return made;
  }
  function changeForm(screen, company2, current, redraw) {
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
      labelled("policy-company", `Type the company id ${company2} to confirm`, typed)
    );
    confirmPanel.hidden = true;
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
      if (!confirmedBy(typed.value, company2)) {
        said.textContent = `Type ${company2} exactly to confirm.`;
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
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "The policy");
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
  async function policyView(screen, company2, message = "") {
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
    const redraw = (said) => void policyView(screen, company2, said);
    show(
      screen.view,
      heading("Sign-in policy"),
      make("p", "lead", "Whether accounts of this company sign in with a second factor. Operators always do."),
      make("dl", "facts", make("dt", "", "Two-factor"), make("dd", "", badge(current))),
      changeForm(screen, company2, current, redraw)
    );
    say(message);
  }

  // src/users-read.ts
  function usersPath(at) {
    const email = at.email?.trim() ?? "";
    if (email !== "") {
      return `api/users?${new URLSearchParams({ email }).toString()}`;
    }
    if (at.after !== null && at.after !== "") {
      return `api/users?${new URLSearchParams({ after: at.after }).toString()}`;
    }
    return "api/users";
  }
  function readUser(body) {
    const user = field(body, "user");
    const email = field(body, "email");
    const emailVerified = field(body, "email_verified");
    const status = field(body, "status");
    if (typeof user !== "string" || user === "" || typeof email !== "string" || typeof emailVerified !== "boolean" || status !== "active" && status !== "disabled") {
      return null;
    }
    return { user, email, emailVerified, status };
  }
  function readUsersPage(body) {
    const listed = field(body, "users");
    const next = field(body, "next");
    if (!Array.isArray(listed) || next !== void 0 && next !== null && typeof next !== "string") {
      return null;
    }
    const users = [];
    for (const item of listed) {
      const read = readUser(item);
      if (read === null) {
        return null;
      }
      users.push(read);
    }
    return { users, next: typeof next === "string" ? next : null };
  }

  // src/users-actions.ts
  function openForm(screen, opened) {
    const keyFor = keys();
    const email = make("input", "");
    email.type = "email";
    email.required = true;
    email.autocomplete = "off";
    const reason = reasonField("open-reason");
    const said = notice();
    const submit = make("button", "primary", "Open account");
    submit.type = "submit";
    const form = make(
      "form",
      "change-form",
      make("h2", "", "Open an account"),
      labelled("open-email", "Sign-in address", email),
      reason.row,
      said,
      submit
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const why = reasonIn(reason.input, said);
      if (why === null) {
        return;
      }
      submit.disabled = true;
      void change("api/users", keyFor, { email: email.value.trim(), reason: why }).then((answer) => {
        submit.disabled = false;
        if (!screen.live()) {
          return;
        }
        const made = answer.ok ? readOpened(answer.body) : null;
        if (made !== null) {
          opened(made.user);
          return;
        }
        const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer, "This account");
        if (text !== null) {
          said.textContent = text;
          said.hidden = false;
        }
      });
    });
    return form;
  }
  function actionsFor(screen, user, address, redraw) {
    const base = `api/users/${encodeURIComponent(user.user)}`;
    const reason = reasonField("action-reason");
    const said = notice();
    const out = make("div", "");
    const ring = { reveal: keys(), enrol: keys(), move: keys() };
    const refusedHere = (answer) => {
      const text = refusedText(screen, answer, "This account");
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    };
    const reveal = button("Show the whole address", "secondary", () => {
      const why = reasonIn(reason.input, said);
      if (why === null) {
        return;
      }
      void change(`${base}/email/reveal`, ring.reveal, { reason: why }).then((answer) => {
        const shown2 = answer.ok ? readRevealed(answer.body) : null;
        if (!screen.live()) {
          return;
        }
        if (shown2 === null) {
          refusedHere(answer);
          return;
        }
        ring.reveal = keys();
        address.textContent = shown2.email;
        say("The whole address is shown, and the showing is recorded with your reason.");
      });
    });
    const enrol = button("Issue an enrolment code", "secondary", () => {
      const why = reasonIn(reason.input, said);
      if (why === null) {
        return;
      }
      void change(`${base}/enrolment`, ring.enrol, { reason: why }).then((answer) => {
        if (!screen.live()) {
          return;
        }
        const issued = answer.ok ? readIssued(answer.body) : null;
        if (issued === null) {
          refusedHere(answer);
          return;
        }
        ring.enrol = keys();
        out.replaceChildren(
          make(
            "div",
            "panel",
            make("p", "", "Enrolment code, shown this once:"),
            make("p", "secret", make("code", "", issued.code)),
            make(
              "p",
              "hint",
              `It lets the person set a password within ${issued.validHours} hours. Give it to them over a channel you trust; a new code replaces this one.`
            )
          )
        );
        say("Enrolment code issued.");
      });
    });
    const move = (path) => {
      const why = reasonIn(reason.input, said);
      if (why === null) {
        return;
      }
      void change(`${base}/${path}`, ring.move, { reason: why }).then((answer) => {
        if (!screen.live()) {
          return;
        }
        if (!answer.ok) {
          refusedHere(answer);
          return;
        }
        if (path === "enable") {
          redraw("Account enabled.");
          return;
        }
        const ended = readDisabled(answer.body);
        const until = ended === null ? null : new Date(ended.accessTokensEndBy * 1e3).toLocaleTimeString();
        redraw(
          ended === null || until === null ? "Account disabled." : `Account disabled: ${ended.sessions} sessions and ${ended.families} refresh families ended; access tokens it already holds stop working by ${until}.`
        );
      });
    };
    const confirmPanel = make(
      "div",
      "confirm",
      make(
        "p",
        "",
        "Disable ",
        make("code", "", user.email),
        "? Its sessions end, its refresh tokens stop working, and every application it signed in to is told."
      )
    );
    confirmPanel.hidden = true;
    const stay = button("Keep it active", "secondary", () => {
      confirmPanel.hidden = true;
      disable.focus();
    });
    confirmPanel.append(
      make(
        "div",
        "actions",
        button("Disable the account", "danger", () => move("disable")),
        stay
      )
    );
    const disable = button("Disable account", "secondary", () => {
      if (reasonIn(reason.input, said) === null) {
        return;
      }
      confirmPanel.hidden = false;
      stay.focus();
    });
    const enable = button("Enable account", "secondary", () => move("enable"));
    const buttons = make("div", "actions", reveal, enrol, user.status === "active" ? disable : enable);
    const title = make("h2", "", "Change this account");
    return make("section", "change-form", title, reason.row, said, buttons, confirmPanel, out);
  }

  // src/users.ts
  var pending = "";
  function statusBadge2(user) {
    const badge2 = make("span", "badge", user.status === "active" ? "Active" : "Disabled");
    badge2.dataset["state"] = user.status === "active" ? "ok" : "warn";
    return badge2;
  }
  function lookup(email) {
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
  function table(users) {
    const head = make(
      "tr",
      "",
      make("th", "", "Address"),
      make("th", "", "Verified"),
      make("th", "", "State"),
      make("th", "", "Account")
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
          make("td", "", statusBadge2(user)),
          make("td", "", link(`#/users/${encodeURIComponent(user.user)}`, user.user, "mono-link"))
        )
      );
    }
    return make("table", "grid", make("thead", "", head), body);
  }
  async function usersView(screen, email, after) {
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
    const parts = [heading("Users"), lookup(email)];
    if (page.users.length === 0) {
      parts.push(
        make(
          "p",
          "empty",
          looking ? "No account in this company has this address." : "This company has no accounts on this page."
        )
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
      })
    );
    show(screen.view, ...parts);
    say("");
  }
  async function userView(screen, id, message = "") {
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
      make("dd", "", statusBadge2(user))
    );
    const redraw = (said) => void userView(screen, id, said);
    show(
      screen.view,
      heading("Account"),
      facts,
      actionsFor(screen, user, address, redraw),
      make("p", "paging", link("#/users", "Back to users"))
    );
    say(message !== "" ? message : pending);
    pending = "";
  }

  // src/console.ts
  var view = element("view", HTMLElement);
  var sections = element("sections", HTMLElement);
  var signOut = element("sign-out", HTMLButtonElement);
  var theme = element("theme", HTMLButtonElement);
  var company = decodeURIComponent(location.pathname.split("/")[2] ?? "");
  var me = null;
  var generation = 0;
  function sectionOf(at) {
    switch (at.kind) {
      case "user":
        return "users";
      case "overview":
        return null;
      default:
        return at.kind;
    }
  }
  function navigate(who, at) {
    const open = offered(who.roles);
    const current = sectionOf(at);
    for (const anchor of sections.querySelectorAll("[data-section]")) {
      const section = anchor.dataset["section"] ?? "";
      anchor.hidden = !open.some((name) => name === section);
      if (section === current) {
        anchor.setAttribute("aria-current", "page");
      } else {
        anchor.removeAttribute("aria-current");
      }
    }
    sections.hidden = false;
    signOut.hidden = false;
  }
  function signedOut(text) {
    generation += 1;
    me = null;
    sections.hidden = true;
    signOut.hidden = true;
    show(
      view,
      heading("Sign in to the console"),
      make("p", "lead", `Operators of ${company} sign in through the company's own sign-in, with a second factor.`),
      make("p", "", link("signin", "Sign in", "button-link"))
    );
    say(text);
  }
  function overview(who) {
    const roles = make("ul", "pills");
    for (const role of who.roles) {
      roles.append(make("li", "pill", role));
    }
    const places = make("ul", "places");
    for (const section of offered(who.roles)) {
      const anchor = sections.querySelector(`[data-section="${section}"]`);
      places.append(make("li", "", link(`#/${section}`, anchor?.textContent ?? section)));
    }
    show(
      view,
      heading(company),
      make("p", "lead", "Signed in as ", make("code", "", who.user), "."),
      make("h2", "", "Your roles"),
      who.roles.length > 0 ? roles : make("p", "muted", "No roles: you can see the operators list only."),
      make("h2", "", "Go to"),
      places
    );
  }
  function draw(who) {
    generation += 1;
    const drawn = generation;
    const screen = { view, live: () => drawn === generation, signedOut: () => signedOut("") };
    const at = route(location.hash);
    navigate(who, at);
    switch (at.kind) {
      case "users":
        void usersView(screen, at.email, at.after);
        return;
      case "user":
        void userView(screen, at.id);
        return;
      case "clients":
        void clientsView(screen, at.after);
        return;
      case "operators":
        void operatorsView(screen, who, at.after);
        return;
      case "policy":
        void policyView(screen, company);
        return;
      case "audit":
        void auditView(screen, at.after);
        return;
      case "companies":
        void companiesView(screen, company, at.after);
        return;
      default:
        overview(who);
    }
  }
  async function start() {
    say("Loading the console.");
    const answer = await call("GET", "api/me");
    if (answer.status === 401) {
      signedOut("");
      return;
    }
    me = answer.ok ? readMe(answer.body) : null;
    if (me === null) {
      show(view, heading("The console could not load"), make("p", "lead", "The server did not answer. Try again."));
      say("");
      return;
    }
    say("");
    draw(me);
  }
  signOut.addEventListener("click", () => {
    void call("POST", "signout").then((answer) => {
      signedOut(answer.ok ? "Signed out." : "The sign-out did not reach the server; close this window to be sure.");
    });
  });
  function label() {
    const dark = document.documentElement.dataset["theme"] === "dark" || document.documentElement.dataset["theme"] !== "light" && matchMedia("(prefers-color-scheme: dark)").matches;
    theme.textContent = dark ? "Light theme" : "Dark theme";
  }
  theme.addEventListener("click", () => {
    const dark = theme.textContent === "Dark theme";
    document.documentElement.dataset["theme"] = dark ? "dark" : "light";
    label();
  });
  addEventListener("hashchange", () => {
    if (me !== null) {
      draw(me);
    }
  });
  element("company", HTMLParagraphElement).textContent = company;
  label();
  void start();
})();
