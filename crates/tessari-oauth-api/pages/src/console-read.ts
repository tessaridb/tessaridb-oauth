// What the admin console's shell decides, kept apart from the document so it can be tested without a browser: who
// it is signed in as, which sections that operator's roles can use, and which view the address names. The server
// refuses what a role cannot do whatever is offered here; offering less only spares the operator a refusal.

import { field, strings } from "./flow.ts";

/** The operator roles the console knows, as the server names them. */
export type Role = "users" | "clients" | "policy" | "keys" | "audit" | "companies";

const ROLES: readonly Role[] = ["users", "clients", "policy", "keys", "audit", "companies"];

/** Who the console is signed in as. */
export interface Me {
  user: string;
  roles: Role[];
}

/** A section of the console, named for the job it serves. */
export type Section =
  | "users"
  | "groups"
  | "clients"
  | "operators"
  | "policy"
  | "branding"
  | "mail"
  | "keys"
  | "audit"
  | "companies";

/** The role a section needs; operators lists the grants of whatever roles the viewer holds, so it needs none. */
const NEEDS: readonly [Section, Role | null][] = [
  ["users", "users"],
  ["groups", "users"],
  ["clients", "clients"],
  ["operators", null],
  ["policy", "policy"],
  ["branding", "policy"],
  ["mail", "policy"],
  ["keys", "keys"],
  ["audit", "audit"],
  ["companies", "companies"],
];

/** The view an address names. */
export type Route =
  | { kind: "overview" }
  | { kind: "users"; email: string | null; after: string | null }
  | { kind: "user"; id: string }
  | { kind: "groups"; after: string | null }
  | { kind: "group"; id: string; after: string | null }
  | { kind: "clients"; after: string | null }
  | { kind: "operators"; after: string | null }
  | { kind: "policy" }
  | { kind: "branding" }
  | { kind: "mail" }
  | { kind: "keys" }
  | { kind: "audit"; after: number | null }
  | { kind: "companies"; after: string | null };

/** Whether `name` is a role the console knows. */
export function isRole(name: string): name is Role {
  return ROLES.some((role) => role === name);
}

/** `GET api/me`'s answer: the user and the roles among them the console knows, or null for any other shape. */
export function readMe(body: unknown): Me | null {
  const user = field(body, "user");
  const roles = strings(field(body, "roles"));
  if (typeof user !== "string" || user === "" || roles === null) {
    return null;
  }
  return { user, roles: roles.filter(isRole) };
}

/** The sections `roles` can use, in the order the console lists them. */
export function offered(roles: readonly Role[]): Section[] {
  return NEEDS.filter(([, need]) => need === null || roles.includes(need)).map(([section]) => section);
}

/** The view `hash` names; anything the console does not know is the overview. */
export function route(hash: string): Route {
  const [path = "", search = ""] = hash.replace(/^#/, "").split("?", 2);
  const query = new URLSearchParams(search);
  const parts = path.split("/").filter((part) => part !== "");
  const [section, id] = parts;
  if (section === "users" && id !== undefined && parts.length === 2) {
    return { kind: "user", id: decodeURIComponent(id) };
  }
  if (section === "groups" && id !== undefined && parts.length === 2) {
    return { kind: "group", id: decodeURIComponent(id), after: query.get("after") };
  }
  switch (parts.length === 1 ? section : undefined) {
    case "users":
      return { kind: "users", email: query.get("email"), after: query.get("after") };
    case "groups":
      return { kind: "groups", after: query.get("after") };
    case "clients":
      return { kind: "clients", after: query.get("after") };
    case "operators":
      return { kind: "operators", after: query.get("after") };
    case "policy":
      return { kind: "policy" };
    case "branding":
      return { kind: "branding" };
    case "mail":
      return { kind: "mail" };
    case "keys":
      return { kind: "keys" };
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

/** What a refusal leaves the operator to do. */
export type ConsoleRefusal =
  | { kind: "signed_out" }
  | { kind: "role" }
  | { kind: "not_found" }
  | { kind: "throttled"; seconds: number | null }
  | { kind: "refused"; code: string }
  | { kind: "failed" };

/** Read a refusal from its `status`, `body` and `Retry-After`; anything the console cannot place is a failure. */
export function readRefusal(status: number, body: unknown, retryAfter: string | null): ConsoleRefusal {
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

/** Whether `typed` is the company id `company`, as a company-wide change (a policy, a suspension) is confirmed. */
export function confirmedBy(typed: string, company: string): boolean {
  return typed.trim() === company && company !== "";
}
