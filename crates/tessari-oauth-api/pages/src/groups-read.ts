// What the groups views decide, kept apart from the document: the pages the server answers, their addresses, and the
// group a form describes. The form is checked for what the operator can fix here; the server reads every name again
// by its own types and refuses whatever this misses.

import { field, strings } from "./flow.ts";

/** One group as the console shows it. */
export interface Group {
  id: string;
  description: string;
  roles: string[];
}

/** One member as the console shows it. */
export interface Member {
  user: string;
  addedBy: string;
}

/** The form field a refusal points at. */
export type GroupField = "id" | "roles";

/** A group id or a role: 1 to 64 lowercase letters, digits, `-` and `_`, starting with a letter or digit. */
const NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** The address of the groups page after `after`. */
export function groupsPath(after: string | null): string {
  return after === null ? "api/groups" : `api/groups?${new URLSearchParams({ after }).toString()}`;
}

/** The address of the group `id`. */
export function groupPath(id: string): string {
  return `api/groups/${encodeURIComponent(id)}`;
}

/** The address of the members page of `id` after the member `after`. */
export function membersPath(id: string, after: string | null): string {
  const base = `${groupPath(id)}/members`;
  return after === null ? base : `${base}?${new URLSearchParams({ after }).toString()}`;
}

/** One group as `GET api/groups/{id}` answers it, or null for any other shape. */
export function readGroup(value: unknown): Group | null {
  const id = field(value, "group");
  const description = field(value, "description");
  const roles = strings(field(value, "roles"));
  if (typeof id !== "string" || id === "" || typeof description !== "string" || roles === null) {
    return null;
  }
  return { id, description, roles };
}

/** `GET api/groups`'s answer, or null when any part of it is not the shape the console knows. */
export function readGroupsPage(body: unknown): { groups: Group[]; next: string | null } | null {
  const listed = field(body, "groups");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== null && typeof next !== "string")) {
    return null;
  }
  const groups: Group[] = [];
  for (const value of listed) {
    const group = readGroup(value);
    if (group === null) {
      return null;
    }
    groups.push(group);
  }
  return { groups, next };
}

/** `GET api/groups/{id}/members`'s answer, or null when any part of it is not the shape the console knows. */
export function readMembersPage(body: unknown): { members: Member[]; next: string | null } | null {
  const listed = field(body, "members");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== null && typeof next !== "string")) {
    return null;
  }
  const members: Member[] = [];
  for (const value of listed) {
    const user = field(value, "user");
    const addedBy = field(value, "added_by");
    if (typeof user !== "string" || user === "" || typeof addedBy !== "string") {
      return null;
    }
    members.push({ user, addedBy });
  }
  return { members, next };
}

/** The request body a group form describes (without the reason), or the field to fix. */
export function groupFormOf(form: { id: string; description: string; roles: string }):
  | { body: { group: string; description: string; roles: string[] } }
  | { wrong: GroupField } {
  const id = form.id.trim();
  if (!NAME.test(id)) {
    return { wrong: "id" };
  }
  const roles = rolesOf(form.roles);
  if (roles === null) {
    return { wrong: "roles" };
  }
  return { body: { group: id, description: form.description.trim(), roles } };
}

/** The roles `text` holds, one per space or line, or null when one is outside the grammar. */
export function rolesOf(text: string): string[] | null {
  const roles = text.split(/\s+/).filter((role) => role !== "");
  return roles.every((role) => NAME.test(role)) ? roles : null;
}
