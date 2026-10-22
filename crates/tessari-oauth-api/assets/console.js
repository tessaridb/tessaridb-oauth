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
        return { kind: "operators" };
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
      const seconds = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      return { kind: "throttled", seconds };
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
  async function call(method, path, body) {
    const init = {
      method,
      credentials: "same-origin",
      cache: "no-store",
      headers: { accept: "application/json", "content-type": "application/json" }
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

  // src/users.ts
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
    show(screen.view, ...parts);
    say("");
  }
  async function userView(screen, id) {
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
    const facts = make(
      "dl",
      "facts",
      make("dt", "", "Account"),
      make("dd", "", make("code", "", user.user)),
      make("dt", "", "Address"),
      make("dd", "", make("code", "", user.email)),
      make("dt", "", "Verified"),
      make("dd", "", user.emailVerified ? "Yes" : "No"),
      make("dt", "", "State"),
      make("dd", "", statusBadge(user))
    );
    show(screen.view, heading("Account"), facts, make("p", "paging", link("#/users", "Back to users")));
    say("");
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
