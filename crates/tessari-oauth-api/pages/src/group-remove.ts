// Deleting a group from its view. It cannot be undone and it ends every membership, and with them the group and
// role claims the members' applications read, so the panel first reads how many members there are, names the group,
// asks for its id typed out and a reason, and only then offers the deletion.

import { groupRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedText } from "./console-change.ts";
import { type Screen, button, labelled, make } from "./console-dom.ts";
import { confirmedBy } from "./console-read.ts";
import { call, say } from "./dom.ts";
import {
  type Group,
  groupPath,
  groupRefusalCode,
  membersCountText,
  membersPath,
  readMembersPage,
} from "./groups-read.ts";

/** Draw into `host`, in place of `opener`, the panel deleting `group`; `deleted` leaves for the groups list. */
export async function deletePanel(
  screen: Screen,
  group: Group,
  { host, opener }: { host: HTMLElement; opener: HTMLElement },
  deleted: (message: string) => void,
): Promise<void> {
  say(`Counting the members of ${group.id}.`);
  const read = await call("GET", membersPath(group.id, null));
  if (!screen.live()) {
    return;
  }
  const page = read.ok ? readMembersPage(read.body) : null;
  if (page === null) {
    const text = read.ok
      ? "The server answered in a shape the console cannot read."
      : refusedText(screen, read, "That group", groupRefusalText);
    if (text !== null) {
      say(text);
    }
    return;
  }
  const keyFor = keys();
  const typed = make("input", "mono");
  typed.type = "text";
  typed.autocomplete = "off";
  typed.spellcheck = false;
  const reason = reasonField("group-delete-reason");
  const said = notice();
  const remove = button("Delete the group", "danger", () => {
    if (!confirmedBy(typed.value, group.id)) {
      return;
    }
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    remove.disabled = true;
    void change(`${groupPath(group.id)}/remove`, keyFor, { reason: why }).then((answer) => {
      remove.disabled = false;
      if (!screen.live()) {
        return;
      }
      if (answer.ok) {
        deleted(`Group ${group.id} deleted.`);
        return;
      }
      const missing = groupRefusalCode(answer.status, answer.body);
      const text = missing !== null
        ? groupRefusalText(missing)
        : refusedText(screen, answer, "That group", groupRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  remove.disabled = true;
  typed.addEventListener("input", () => {
    remove.disabled = !confirmedBy(typed.value, group.id);
  });
  const keep = button("Keep it", "secondary", () => {
    host.replaceChildren();
    opener.hidden = false;
    say(`${group.id} kept.`);
  });
  opener.hidden = true;
  host.replaceChildren(
    make(
      "section",
      "change-form confirm",
      make("h2", "", "Delete ", make("code", "", group.id), "?"),
      make(
        "p",
        "",
        `${membersCountText(page.members.length, page.next !== null)} Applications stop receiving this group and ` +
          "its roles for those accounts at their next request. This cannot be undone.",
      ),
      labelled("group-delete-typed", "Type the group id to confirm", typed),
      reason.row,
      said,
      make("div", "actions", remove, keep),
    ),
  );
  typed.focus();
  say(`Confirm deleting ${group.id}.`);
}
