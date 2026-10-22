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

  // src/console.ts
  var view = element("view", HTMLElement);
  var sections = element("sections", HTMLElement);
  var signOut = element("sign-out", HTMLButtonElement);
  var theme = element("theme", HTMLButtonElement);
  var company = decodeURIComponent(location.pathname.split("/")[2] ?? "");
  var me = null;
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
    const at = route(location.hash);
    navigate(who, at);
    overview(who);
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
