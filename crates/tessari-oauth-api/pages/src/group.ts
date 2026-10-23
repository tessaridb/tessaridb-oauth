// One group: what it is, the roles it carries, and its members a page at a time behind the server's cursor. Every
// change carries a reason and an Idempotency-Key. Taking a member out is undone by adding them again, so it acts
// at once; deleting the group ends every membership and cannot be undone, so it has its own confirming panel.

import { groupRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, button, heading, labelled, link, make, show } from "./console-dom.ts";
import { type Answer, call, say } from "./dom.ts";
import { deletePanel } from "./group-remove.ts";
import {
  type Group,
  type Member,
  groupPath,
  groupRefusalCode,
  membersPath,
  readGroup,
  readMembersPage,
  rolesOf,
} from "./groups-read.ts";

/** What the next group view says once drawn: the outcome of the change that led to it. */
let pending = "";

/** The address of the group `id`'s own view. */
export function groupHash(id: string): string {
  return `#/groups/${encodeURIComponent(id)}`;
}

/** Open the group `id`'s view, saying `message` once it is drawn. */
export function openGroup(id: string, message: string): void {
  pending = message;
  location.hash = groupHash(id);
}

/** `roles` as pills, or a muted word when there are none. */
export function rolePills(roles: readonly string[]): HTMLElement {
  if (roles.length === 0) {
    return make("span", "muted", "None");
  }
  const pills = make("ul", "pills");
  for (const role of roles) {
    pills.append(make("li", "pill", role));
  }
  return pills;
}

/** Say on `said` why `answer` was refused, unless the session ended and `screen` signs out instead. */
function refusedHere(screen: Screen, answer: Answer, said: HTMLParagraphElement): void {
  const missing = groupRefusalCode(answer.status, answer.body);
  const text = answer.ok
    ? "The server answered in a shape the console cannot read."
    : missing !== null
      ? groupRefusalText(missing)
      : refusedText(screen, answer, "This group", groupRefusalText);
  if (text !== null) {
    said.textContent = text;
    said.hidden = false;
  }
}

/** The form setting the roles `group` carries; `redraw` shows the group afresh with a message. */
function rolesForm(screen: Screen, group: Group, redraw: (message: string) => void): HTMLFormElement {
  const keyFor = keys();
  const roles = make("input", "mono");
  roles.type = "text";
  roles.autocomplete = "off";
  roles.spellcheck = false;
  roles.value = group.roles.join(" ");
  const reason = reasonField("group-roles-reason");
  const said = notice();
  const submit = make("button", "secondary", "Set roles");
  submit.type = "submit";
  const form = make(
    "form",
    "change-form",
    make("h2", "", "Roles it carries"),
    labelled("group-roles", "Roles, separated by spaces (empty for none)", roles),
    reason.row,
    said,
    submit,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const set = rolesOf(roles.value);
    if (set === null) {
      said.textContent = "Give roles as lowercase words separated by spaces, each like a group id.";
      said.hidden = false;
      roles.setAttribute("aria-invalid", "true");
      roles.focus();
      return;
    }
    roles.removeAttribute("aria-invalid");
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    submit.disabled = true;
    void change(`${groupPath(group.id)}/roles`, keyFor, { roles: set, reason: why }).then((answer) => {
      submit.disabled = false;
      if (!screen.live()) {
        return;
      }
      if (answer.ok && readGroup(answer.body) !== null) {
        redraw("Roles set.");
        return;
      }
      refusedHere(screen, answer, said);
    });
  });
  return form;
}

/** The members on this page with a removal each, and the form adding one by account id. */
function membersSection(
  screen: Screen,
  group: Group,
  page: { members: Member[]; next: string | null },
  after: string | null,
  redraw: (message: string) => void,
): HTMLElement {
  const keyFor = keys();
  const reason = reasonField("group-members-reason");
  const said = notice();
  const send = (path: string, body: Record<string, unknown>, done: string, sent: HTMLButtonElement): void => {
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    sent.disabled = true;
    void change(path, keyFor, { ...body, reason: why }).then((answer) => {
      sent.disabled = false;
      if (!screen.live()) {
        return;
      }
      if (answer.ok) {
        redraw(done);
        return;
      }
      refusedHere(screen, answer, said);
    });
  };
  const base = groupPath(group.id);
  const parts: Node[] = [make("h2", "", "Members")];
  if (page.members.length === 0) {
    parts.push(make("p", "empty", after === null ? "No account is in this group." : "No more members after this one."));
  } else {
    const head = make("tr", "", make("th", "", "Account"), make("th", "", "Added by"), make("th", "", "Membership"));
    for (const cell of head.children) {
      cell.setAttribute("scope", "col");
    }
    const body = make("tbody", "");
    for (const member of page.members) {
      const remove = button("Take out", "secondary", () => {
        send(`${base}/members/${encodeURIComponent(member.user)}/remove`, {}, `${member.user} taken out.`, remove);
      });
      remove.setAttribute("aria-label", `Take ${member.user} out of ${group.id}`);
      body.append(
        make(
          "tr",
          "",
          make("td", "", link(`#/users/${encodeURIComponent(member.user)}`, member.user, "mono-link")),
          make("td", "", make("code", "", member.addedBy)),
          make("td", "", remove),
        ),
      );
    }
    parts.push(make("table", "grid", make("thead", "", head), body));
  }
  const paging = make("p", "paging");
  if (after !== null) {
    paging.append(link(groupHash(group.id), "First page"));
  }
  if (page.next !== null) {
    paging.append(link(`${groupHash(group.id)}?${new URLSearchParams({ after: page.next }).toString()}`, "Next page"));
  }
  if (paging.childElementCount > 0) {
    parts.push(paging);
  }
  const user = make("input", "mono");
  user.type = "text";
  user.autocomplete = "off";
  user.spellcheck = false;
  const add = make("button", "secondary", "Add member");
  add.type = "submit";
  const form = make("form", "inline-form", labelled("group-add-user", "Account id", user), add);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const typed = user.value.trim();
    if (typed === "") {
      said.textContent = "Give the account's id, as the Users view shows it.";
      said.hidden = false;
      user.focus();
      return;
    }
    send(`${base}/members`, { user: typed }, `${typed} added.`, add);
  });
  parts.push(reason.row, form, said);
  return make("section", "change-form", ...parts);
}

/** One group by its id with the members page after `after`, and `message` said once it is drawn. */
export async function groupView(screen: Screen, id: string, after: string | null, message = ""): Promise<void> {
  say("Loading the group.");
  const [read, listed] = await Promise.all([call("GET", groupPath(id)), call("GET", membersPath(id, after))]);
  if (!screen.live()) {
    return;
  }
  if (!read.ok || !listed.ok) {
    refusedOn(screen, "Group", read.ok ? listed : read, "That group");
    return;
  }
  const group = readGroup(read.body);
  const page = readMembersPage(listed.body);
  if (group === null || page === null) {
    unreadable(screen, "Group");
    return;
  }
  const facts = make(
    "dl",
    "facts",
    make("dt", "", "Group"),
    make("dd", "", make("code", "", group.id)),
    make("dt", "", "Description"),
    make("dd", "", group.description === "" ? make("span", "muted", "None") : group.description),
    make("dt", "", "Roles"),
    make("dd", "", rolePills(group.roles)),
  );
  const redraw = (said: string): void => void groupView(screen, id, after, said);
  const host = make("div", "");
  const opener = make("section", "change-form", make("h2", "", "Delete this group"));
  const remove = button("Delete group", "secondary", () => {
    void deletePanel(screen, group, { host, opener }, (said) => {
      pending = said;
      location.hash = "#/groups";
    });
  });
  opener.append(make("div", "actions", remove));
  show(
    screen.view,
    heading("Group"),
    facts,
    rolesForm(screen, group, redraw),
    membersSection(screen, group, page, after, redraw),
    opener,
    host,
    make("p", "paging", link("#/groups", "Back to groups")),
  );
  say(message !== "" ? message : pending);
  pending = "";
}

/** What the groups list says once drawn after a deletion, read once. */
export function takePending(): string {
  const said = pending;
  pending = "";
  return said;
}
