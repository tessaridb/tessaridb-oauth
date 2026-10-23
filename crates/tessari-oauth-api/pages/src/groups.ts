// The groups list: the company's groups a page at a time in id order behind the server's cursor, with no total, and
// the form making a new one. A group's roles are labels released to applications that ask for the `groups` scope;
// they grant nothing in this console.

import { groupRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, heading, labelled, link, make, show } from "./console-dom.ts";
import { call, say } from "./dom.ts";
import { groupHash, openGroup, rolePills, takePending } from "./group.ts";
import { type Group, type GroupField, groupFormOf, groupsPath, readGroup, readGroupsPage } from "./groups-read.ts";

/** What each form field says when it holds something a group cannot take. */
const WRONG: Record<GroupField, string> = {
  id: "Give an id of 1 to 64 lowercase letters, digits, - and _, starting with a letter or digit.",
  roles: "Give roles as lowercase words separated by spaces, each like a group id.",
};

/** The groups as a table: id, description, roles, and a link to each. */
function table(groups: readonly Group[]): HTMLTableElement {
  const head = make(
    "tr",
    "",
    make("th", "", "Group"),
    make("th", "", "Description"),
    make("th", "", "Roles"),
  );
  for (const cell of head.children) {
    cell.setAttribute("scope", "col");
  }
  const body = make("tbody", "");
  for (const group of groups) {
    body.append(
      make(
        "tr",
        "",
        make("td", "", link(groupHash(group.id), group.id, "mono-link")),
        make("td", "", group.description === "" ? make("span", "muted", "None") : group.description),
        make("td", "", rolePills(group.roles)),
      ),
    );
  }
  return make("table", "grid", make("thead", "", head), body);
}

/** The form making a group; the new group's view follows. */
function makeForm(screen: Screen): HTMLFormElement {
  const keyFor = keys();
  const id = make("input", "mono");
  id.type = "text";
  id.autocomplete = "off";
  id.spellcheck = false;
  id.maxLength = 64;
  const description = make("input", "");
  description.type = "text";
  description.autocomplete = "off";
  description.maxLength = 200;
  const roles = make("input", "mono");
  roles.type = "text";
  roles.autocomplete = "off";
  roles.spellcheck = false;
  const reason = reasonField("group-make-reason");
  const said = notice();
  const submit = make("button", "primary", "Make group");
  submit.type = "submit";
  const form = make(
    "form",
    "change-form",
    make("h2", "", "Make a group"),
    labelled("group-make-id", "Group id", id),
    labelled("group-make-description", "Description (optional)", description),
    labelled("group-make-roles", "Roles it carries (optional, separated by spaces)", roles),
    reason.row,
    said,
    submit,
  );
  const fields: Record<GroupField, HTMLInputElement> = { id, roles };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    for (const input of Object.values(fields)) {
      input.removeAttribute("aria-invalid");
    }
    const described = groupFormOf({ id: id.value, description: description.value, roles: roles.value });
    if ("wrong" in described) {
      said.textContent = WRONG[described.wrong];
      said.hidden = false;
      fields[described.wrong].setAttribute("aria-invalid", "true");
      fields[described.wrong].focus();
      return;
    }
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    submit.disabled = true;
    void change("api/groups", keyFor, { ...described.body, reason: why }).then((answer) => {
      submit.disabled = false;
      if (!screen.live()) {
        return;
      }
      const group = answer.ok ? readGroup(answer.body) : null;
      if (group !== null) {
        openGroup(group.id, "Group made.");
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "This group", groupRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  return form;
}

/** The groups list for a route: the page after `after`. */
export async function groupsView(screen: Screen, after: string | null): Promise<void> {
  say("Loading groups.");
  const answer = await call("GET", groupsPath(after));
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Groups", answer, "That group");
    return;
  }
  const page = readGroupsPage(answer.body);
  if (page === null) {
    unreadable(screen, "Groups");
    return;
  }
  const parts: Node[] = [
    heading("Groups"),
    make(
      "p",
      "lead",
      "A group's roles are released to applications granted the groups scope, for the accounts in it. They grant " +
        "nothing in this console.",
    ),
  ];
  parts.push(
    page.groups.length === 0
      ? make("p", "empty", after === null ? "This company has no groups yet." : "No more groups after this one.")
      : table(page.groups),
  );
  const paging = make("p", "paging");
  if (after !== null) {
    paging.append(link("#/groups", "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`#/groups?${new URLSearchParams({ after: page.next }).toString()}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  parts.push(makeForm(screen));
  show(screen.view, ...parts);
  say(takePending());
}
