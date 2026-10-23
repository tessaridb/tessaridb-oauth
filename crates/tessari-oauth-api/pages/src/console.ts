// The admin console's entry point: one view at a time, chosen by the address's hash, so a reload or a shared link
// lands on the same view. It asks `api/me` who is signed in; without a console session it offers the company's
// sign-in, and signing in comes back here. The browser holds only the session cookie, never a token.

import { type Me, type Route, type Section, offered, readMe, route } from "./console-read.ts";
import { type Screen, heading, link, make, show } from "./console-dom.ts";
import { call, element, say } from "./dom.ts";
import { auditView } from "./audit.ts";
import { companiesView } from "./companies.ts";
import { clientsView } from "./clients.ts";
import { operatorsView } from "./operators.ts";
import { policyView } from "./policy.ts";
import { userView, usersView } from "./users.ts";

const view = element("view", HTMLElement);
const sections = element("sections", HTMLElement);
const signOut = element("sign-out", HTMLButtonElement);
const theme = element("theme", HTMLButtonElement);

/** The company this console serves, from the page's own address `/admin/{company}/`. */
const company = decodeURIComponent(location.pathname.split("/")[2] ?? "");

/** Who is signed in, asked once per page load and forgotten on signing out. */
let me: Me | null = null;

/** Bumped by every draw, so an answer arriving for an older view paints nothing. */
let generation = 0;

/** The section a route belongs to, for marking the navigation. */
function sectionOf(at: Route): Section | null {
  switch (at.kind) {
    case "user":
      return "users";
    case "group":
      return "groups";
    case "overview":
      return null;
    default:
      return at.kind;
  }
}

/** Offer the sections `who` can use and mark the one `at` belongs to. */
function navigate(who: Me, at: Route): void {
  const open = offered(who.roles);
  const current = sectionOf(at);
  for (const anchor of sections.querySelectorAll<HTMLAnchorElement>("[data-section]")) {
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

/** The signed-out state: nothing offered but the company's sign-in. */
function signedOut(text: string): void {
  generation += 1;
  me = null;
  sections.hidden = true;
  signOut.hidden = true;
  show(
    view,
    heading("Sign in to the console"),
    make("p", "lead", `Operators of ${company} sign in through the company's own sign-in, with a second factor.`),
    make("p", "", link("signin", "Sign in", "button-link")),
  );
  say(text);
}

/** The overview: who is signed in, the roles held, and where each leads. */
function overview(who: Me): void {
  const roles = make("ul", "pills");
  for (const role of who.roles) {
    roles.append(make("li", "pill", role));
  }
  const places = make("ul", "places");
  for (const section of offered(who.roles)) {
    const anchor = sections.querySelector<HTMLAnchorElement>(`[data-section="${section}"]`);
    places.append(make("li", "", link(`#/${section}`, anchor?.textContent ?? section)));
  }
  show(
    view,
    heading(company),
    make("p", "lead", "Signed in as ", make("code", "", who.user), "."),
    make("h2", "", "Your roles"),
    who.roles.length > 0 ? roles : make("p", "muted", "No roles: you can see the operators list only."),
    make("h2", "", "Go to"),
    places,
  );
}

/** Draw the view the address names for `who`. */
function draw(who: Me): void {
  generation += 1;
  const drawn = generation;
  const screen: Screen = { view, live: () => drawn === generation, signedOut: () => signedOut("") };
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

/** Ask who is signed in, then draw; a refusal for want of a session offers the sign-in. */
async function start(): Promise<void> {
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

/** The theme the page shows now, and the label offering the other one. */
function label(): void {
  const dark = document.documentElement.dataset["theme"] === "dark"
    || (document.documentElement.dataset["theme"] !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
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
