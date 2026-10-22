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
      case "operators":
        return { kind: "operators", after: query.get("after") };
      case "policy":
        return { kind: "policy" };
      case "audit": {
        const after = query.get("after");
        return { kind: "audit", after: after !== null && /^\d+$/.test(after) ? Number(after) : null };
      }
      case "companies":
        return { kind: "companies" };
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
  function change(path, keyFor, body) {
    return call("POST", path, body, { "idempotency-key": keyFor({ ...body, "@path": path }) });
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
  function day(seconds2) {
    return new Intl.DateTimeFormat(void 0, { dateStyle: "medium" }).format(new Date(seconds2 * 1e3));
  }
  function rolePicker(roles) {
    const group = make("fieldset", "segmented", make("legend", "", "Role"));
    const inputs = [];
    for (const [index, role] of roles.entries()) {
      const input = make("input", "");
      input.type = "radio";
      input.name = "grant-role";
      input.id = `grant-role-${role}`;
      input.value = role;
      input.checked = index === 0;
      const label2 = make("label", "", role);
      label2.htmlFor = input.id;
      group.append(input, label2);
      inputs.push([input, role]);
    }
    return { group, chosen: () => inputs.find(([input]) => input.checked)?.[1] ?? null };
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
          make("td", "", grant.expiresAt === null ? "Never" : day(grant.expiresAt)),
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
        const shown = answer.ok ? readRevealed(answer.body) : null;
        if (!screen.live()) {
          return;
        }
        if (shown === null) {
          refusedHere(answer);
          return;
        }
        ring.reveal = keys();
        address.textContent = shown.email;
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
  function statusBadge(user) {
    const badge = make("span", "badge", user.status === "active" ? "Active" : "Disabled");
    badge.dataset["state"] = user.status === "active" ? "ok" : "warn";
    return badge;
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
          make("td", "", statusBadge(user)),
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
      make("dd", "", statusBadge(user))
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
      case "operators":
        void operatorsView(screen, who, at.after);
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
