// What the users views decide, kept apart from the document: which request a route makes of the users API, and what
// its answers mean. An address arrives masked and stays as given; showing it whole is a separate, recorded request.

import { field } from "./flow.ts";

/** An account's state as the server names it. */
export type Status = "active" | "disabled";

/** One account as the console shows it. */
export interface User {
  user: string;
  email: string;
  emailVerified: boolean;
  status: Status;
}

/** A page of accounts and the cursor of the next one, null when this page is the last. */
export interface UsersPage {
  users: User[];
  next: string | null;
}

/** The users API request for a lookup by exact `email`, a page after `after`, or the first page. */
export function usersPath(at: { email: string | null; after: string | null }): string {
  const email = at.email?.trim() ?? "";
  if (email !== "") {
    return `api/users?${new URLSearchParams({ email }).toString()}`;
  }
  if (at.after !== null && at.after !== "") {
    return `api/users?${new URLSearchParams({ after: at.after }).toString()}`;
  }
  return "api/users";
}

/** One account from an answer, or null when it has another shape. */
export function readUser(body: unknown): User | null {
  const user = field(body, "user");
  const email = field(body, "email");
  const emailVerified = field(body, "email_verified");
  const status = field(body, "status");
  if (
    typeof user !== "string" ||
    user === "" ||
    typeof email !== "string" ||
    typeof emailVerified !== "boolean" ||
    (status !== "active" && status !== "disabled")
  ) {
    return null;
  }
  return { user, email, emailVerified, status };
}

/** A page of accounts, read whole or not at all. */
export function readUsersPage(body: unknown): UsersPage | null {
  const listed = field(body, "users");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== undefined && next !== null && typeof next !== "string")) {
    return null;
  }
  const users: User[] = [];
  for (const item of listed) {
    const read = readUser(item);
    if (read === null) {
      return null;
    }
    users.push(read);
  }
  return { users, next: typeof next === "string" ? next : null };
}
