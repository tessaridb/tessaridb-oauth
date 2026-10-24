// The Keys view: the signing keys of this company's issuer, each in the state the rotation rule gives it, a successor
// made early, and a compromised key withdrawn. A withdrawal cannot be undone and stops every token the key signed, so
// the panel says so, asks for the key's id typed out and a reason, and only then offers it.

import { keyRefusalText } from "./console-copy.ts";
import {
  change,
  keys as idempotencyKeys,
  notice,
  reasonField,
  reasonIn,
  refusedOn,
  refusedText,
  unreadable,
} from "./console-change.ts";
import { type Screen, button, heading, labelled, make, show } from "./console-dom.ts";
import { confirmedBy } from "./console-read.ts";
import { when } from "./copy.ts";
import { call, say } from "./dom.ts";
import { type SigningKey, readKeys, readRotated, readWithdrawn } from "./keys-read.ts";

const PATH = "api/keys";

/** What `key`'s state means, in the operator's words. */
function stateText(key: SigningKey): string {
  switch (key.state) {
    case "signing":
      return "Signs new tokens";
    case "waiting":
      return key.signsFrom === null ? "Published, waiting to sign" : `Published, signs from ${when(key.signsFrom)}`;
    case "previous":
      return "Published for the tokens it signed";
    case "retiring":
      return "No longer published";
    case "withdrawn":
      return "Withdrawn";
  }
}

/** The keys as a table, each not yet withdrawn with a Withdraw action handed to `withdraw`. */
function keysTable(list: readonly SigningKey[], withdraw: (key: SigningKey) => void): HTMLTableElement {
  const head = make(
    "tr",
    "",
    make("th", "", "Key"),
    make("th", "", "Algorithm"),
    make("th", "", "Published"),
    make("th", "", "State"),
    make("th", "", "Actions"),
  );
  for (const cell of head.children) {
    cell.setAttribute("scope", "col");
  }
  const body = make("tbody", "");
  for (const key of list) {
    const action = make("td", "");
    if (key.state !== "withdrawn") {
      const pressed = button("Withdraw", "secondary", () => withdraw(key));
      pressed.setAttribute("aria-label", `Withdraw ${key.kid}`);
      action.append(pressed);
    }
    body.append(
      make(
        "tr",
        "",
        make("td", "", make("code", "", key.kid)),
        make("td", "", key.algorithm),
        make("td", "", when(key.createdAt)),
        make("td", "", key.state === "signing" ? make("span", "pill", stateText(key)) : stateText(key)),
        action,
      ),
    );
  }
  return make("table", "grid", make("thead", "", head), body);
}

/** Draw into `host` the panel withdrawing `key`; `redraw` shows the view afresh with a message. */
function withdrawalPanel(screen: Screen, key: SigningKey, host: HTMLElement, redraw: (message: string) => void): void {
  const keyFor = idempotencyKeys();
  const typed = make("input", "mono");
  typed.type = "text";
  typed.autocomplete = "off";
  typed.spellcheck = false;
  const reason = reasonField("withdraw-reason");
  const said = notice();
  const withdraw = button("Withdraw the key", "danger", () => {
    if (!confirmedBy(typed.value, key.kid)) {
      return;
    }
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    withdraw.disabled = true;
    void change(`${PATH}/${encodeURIComponent(key.kid)}/withdraw`, keyFor, { reason: why }).then((answer) => {
      withdraw.disabled = false;
      if (!screen.live()) {
        return;
      }
      const done = answer.ok ? readWithdrawn(answer.body) : null;
      if (done !== null) {
        redraw(
          done.replacement === null
            ? `Key ${done.withdrawn} withdrawn.`
            : `Key ${done.withdrawn} withdrawn; key ${done.replacement} was made to sign in its place.`,
        );
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "That key", keyRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  withdraw.disabled = true;
  typed.addEventListener("input", () => {
    withdraw.disabled = !confirmedBy(typed.value, key.kid);
  });
  const keep = button("Keep it", "secondary", () => {
    host.replaceChildren();
    say(`Key ${key.kid} kept.`);
  });
  host.replaceChildren(
    make(
      "section",
      "change-form confirm",
      make("h2", "", "Withdraw ", make("code", "", key.kid), "?"),
      make(
        "p",
        "",
        "Do this when the key may have been exposed. It is taken out of the key set at once, so every token it " +
          "signed stops verifying; a service that cached the key set can still accept them for up to five minutes. " +
          "Refresh tokens are not revoked. When no other key can sign, a new one is made first. This cannot be undone.",
      ),
      labelled("withdraw-typed", "Type the key id to confirm", typed),
      reason.row,
      said,
      make("div", "actions", withdraw, keep),
    ),
  );
  typed.focus();
  say(`Confirm withdrawing key ${key.kid}.`);
}

/** The form making a successor now; `redraw` shows the view afresh with a message. */
function rotateForm(screen: Screen, waiting: boolean, redraw: (message: string) => void): HTMLElement {
  if (waiting) {
    return make(
      "section",
      "change-form",
      make("h2", "", "Make a successor"),
      make("p", "", "A successor is already published and waiting. It starts signing by itself."),
    );
  }
  const keyFor = idempotencyKeys();
  const reason = reasonField("rotate-reason");
  const said = notice();
  const start = button("Make a successor now", "primary", () => {
    said.hidden = true;
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    void change(`${PATH}/rotate`, keyFor, { reason: why }).then((answer) => {
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readRotated(answer.body) : null;
      if (made !== null) {
        redraw(`Key ${made.kid} is published and signs from ${when(made.signsFrom)}.`);
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "The key", keyRefusalText);
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  return make(
    "section",
    "change-form",
    make("h2", "", "Make a successor"),
    make(
      "p",
      "",
      "Keys are replaced every 30 days by themselves. A successor made now is published at once and signs five " +
        "minutes later; the key it replaces stays published for an hour so the tokens it signed still verify.",
    ),
    reason.row,
    said,
    make("div", "actions", start),
  );
}

/** The Keys view, with `message` said once it is drawn. */
export async function keysView(screen: Screen, message = ""): Promise<void> {
  say("Loading the signing keys.");
  const answer = await call("GET", PATH);
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Signing keys", answer, "The keys");
    return;
  }
  const list = readKeys(answer.body);
  if (list === null) {
    unreadable(screen, "Signing keys");
    return;
  }
  const redraw = (said: string): void => void keysView(screen, said);
  const withdrawal = make("div", "");
  const withdraw = (key: SigningKey): void => withdrawalPanel(screen, key, withdrawal, redraw);
  show(
    screen.view,
    heading("Signing keys"),
    make("p", "lead", "The keys this company's issuer signs tokens with. No private part of a key is ever shown."),
    list.length === 0 ? make("p", "empty", "No key yet; one is made within five minutes.") : keysTable(list, withdraw),
    withdrawal,
    rotateForm(
      screen,
      list.some((key) => key.state === "waiting"),
      redraw,
    ),
  );
  say(message);
}
