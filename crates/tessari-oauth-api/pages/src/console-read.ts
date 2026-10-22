// What the admin console's shell decides, kept apart from the document so it can be tested without a browser: who
// it is signed in as, which sections that operator's roles can use, and which view the address names. The server
// refuses what a role cannot do whatever is offered here; offering less only spares the operator a refusal.

import { field, strings } from "./flow.ts";

/** The operator roles the console knows, as the server names them. */
export type Role = "users" | "clients" | "policy" | "audit" | "companies";

const ROLES: readonly Role[] = ["users", "clients", "policy", "audit", "companies"];

/** Who the console is signed in as. */
export interface Me {
  user: string;
  roles: Role[];
}

/** A section of the console, named for the job it serves. */
export type Section = "users" | "operators" | "policy" | "audit" | "companies";

/** The role a section needs; operators lists the grants of whatever roles the viewer holds, so it needs none. */
const NEEDS: readonly [Section, Role | null][] = [
  ["users", "users"],
  ["operators", null],
  ["policy", "policy"],
  ["audit", "audit"],
  ["companies", "companies"],
];

/** The view an address names. */
export type Route =
  | { kind: "overview" }
  | { kind: "users"; email: string | null; after: string | null }
  | { kind: "user"; id: string }
  | { kind: "operators" }
  | { kind: "policy" }
  | { kind: "audit"; after: number | null }
  | { kind: "companies" };

function isRole(name: string): name is Role {
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
  switch (parts.length === 1 ? section : undefined) {
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
