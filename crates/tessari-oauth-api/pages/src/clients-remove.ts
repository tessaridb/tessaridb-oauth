// Removing a client from the clients view. It cannot be undone and it ends grants other people gave, so the panel
// first reads how many users hold one, names the client, asks for its id typed out and a reason, and only then
// offers the removal. The server's own console client is never offered.

import { clientRemovalRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedText } from "./console-change.ts";
import { type Screen, button, labelled, make } from "./console-dom.ts";
import { confirmedBy } from "./console-read.ts";
import { call, say } from "./dom.ts";
import { type Client, clientPath, readHolders, readRemoved, removalPath } from "./clients-read.ts";

/** Draw into `host` the panel removing `client`; `redraw` shows the list afresh with a message. */
export async function removalPanel(
  screen: Screen,
  client: Client,
  host: HTMLElement,
  redraw: (message: string) => void,
): Promise<void> {
  say(`Reading who holds a grant to ${client.id}.`);
  const read = await call("GET", clientPath(client.id));
  if (!screen.live()) {
    return;
  }
  const holders = read.ok ? readHolders(read.body) : null;
  if (holders === null) {
    const text = read.ok
      ? "The server answered in a shape the console cannot read."
      : refusedText(screen, read, "That client", clientRemovalRefusalText);
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
  const reason = reasonField("remove-reason");
  const said = notice();
  const remove = button("Remove the client", "danger", () => {
    if (!confirmedBy(typed.value, client.id)) {
      return;
    }
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    remove.disabled = true;
    void change(removalPath(client.id), keyFor, { reason: why }).then((answer) => {
      remove.disabled = false;
      if (!screen.live()) {
        return;
      }
      const removed = answer.ok ? readRemoved(answer.body) : null;
      if (removed !== null) {
        const until = new Date(removed.accessTokensEndBy * 1000).toLocaleTimeString();
        redraw(
          `Client ${removed.clientId} removed: ${removed.consents} grants and ${removed.families} refresh families ` +
            `ended; access tokens it already holds stop working by ${until}.`,
        );
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "That client", clientRemovalRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  remove.disabled = true;
  typed.addEventListener("input", () => {
    remove.disabled = !confirmedBy(typed.value, client.id);
  });
  const keep = button("Keep it", "secondary", () => {
    host.replaceChildren();
    say(`${client.id} kept.`);
  });
  const users = holders === 1 ? "1 user holds" : `${holders} users hold`;
  host.replaceChildren(
    make(
      "section",
      "change-form confirm",
      make("h2", "", "Remove ", make("code", "", client.id), "?"),
      make(
        "p",
        "",
        `${users} a grant to it. Removing it deletes the registration, revokes those grants and every refresh token ` +
          "it holds; access tokens it already has stop working within five minutes. This cannot be undone.",
      ),
      labelled("remove-typed", "Type the client id to confirm", typed),
      reason.row,
      said,
      make("div", "actions", remove, keep),
    ),
  );
  typed.focus();
  say(`Confirm removing ${client.id}.`);
}
