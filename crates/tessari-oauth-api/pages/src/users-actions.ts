// The changes an operator holding `users` makes to accounts. Every change carries a reason and an Idempotency-Key
// made once per form, so a double press is one change. Disabling ends what the account holds elsewhere, so it is
// confirmed with the account named; enabling is undone by disabling and is not. Showing an address whole is
// recorded with the reason, and an enrolment code is shown once and never kept by the page, or sent to the account's
// address so that nobody here sees it.

import { change, keys, notice, reasonField, reasonIn, refusedText } from "./console-change.ts";
import { type Screen, button, labelled, make } from "./console-dom.ts";
import { type Answer, say } from "./dom.ts";
import { type User } from "./users-read.ts";
import { readDisabled, readIssued, readMailed, readOpened, readRevealed } from "./users-change.ts";

/** The form opening an account for an address; the new account's view follows. */
export function openForm(screen: Screen, opened: (user: string) => void): HTMLFormElement {
  const keyFor = keys();
  const email = make("input", "");
  email.type = "email";
  email.required = true;
  email.autocomplete = "off";
  const reason = reasonField("open-reason");
  const said = notice();
  const submit = make("button", "primary", "Open account");
  submit.type = "submit";
  const form = make(
    "form",
    "change-form",
    make("h2", "", "Open an account"),
    labelled("open-email", "Sign-in address", email),
    reason.row,
    said,
    submit,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    submit.disabled = true;
    void change("api/users", keyFor, { email: email.value.trim(), reason: why }).then((answer) => {
      submit.disabled = false;
      if (!screen.live()) {
        return;
      }
      const made = answer.ok ? readOpened(answer.body) : null;
      if (made !== null) {
        opened(made.user);
        return;
      }
      const text = answer.ok
        ? "The server answered in a shape the console cannot read."
        : refusedText(screen, answer, "This account");
      if (text !== null) {
        said.textContent = text;
        said.hidden = false;
      }
    });
  });
  return form;
}

/** The changes offered for `user`, drawn into the detail view; `redraw` shows the account afresh with a message. */
export function actionsFor(
  screen: Screen,
  user: User,
  address: HTMLElement,
  redraw: (message: string) => void,
): HTMLElement {
  const base = `api/users/${encodeURIComponent(user.user)}`;
  const reason = reasonField("action-reason");
  const said = notice();
  const out = make("div", "");
  const ring = { reveal: keys(), enrol: keys(), mail: keys(), move: keys() };

  const refusedHere = (answer: Answer): void => {
    const text = refusedText(screen, answer, "This account");
    if (text !== null) {
      said.textContent = text;
      said.hidden = false;
    }
  };

  const reveal = button("Show the whole address", "secondary", () => {
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    void change(`${base}/email/reveal`, ring.reveal, { reason: why }).then((answer) => {
      const shown = answer.ok ? readRevealed(answer.body) : null;
      if (!screen.live()) {
        return;
      }
      if (shown === null) {
        refusedHere(answer);
        return;
      }
      ring.reveal = keys();
      address.textContent = shown.email;
      say("The whole address is shown, and the showing is recorded with your reason.");
    });
  });

  const enrol = button("Issue an enrolment code", "secondary", () => {
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    void change(`${base}/enrolment`, ring.enrol, { reason: why }).then((answer) => {
      if (!screen.live()) {
        return;
      }
      const issued = answer.ok ? readIssued(answer.body) : null;
      if (issued === null) {
        refusedHere(answer);
        return;
      }
      ring.enrol = keys();
      out.replaceChildren(
        make(
          "div",
          "panel",
          make("p", "", "Enrolment code, shown this once:"),
          make("p", "secret", make("code", "", issued.code)),
          make(
            "p",
            "hint",
            `It lets the person set a password within ${issued.validHours} hours. Give it to them over a channel ` +
              "you trust; a new code replaces this one.",
          ),
        ),
      );
      say("Enrolment code issued.");
    });
  });

  const mail = button("Send the code by mail", "secondary", () => {
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    void change(`${base}/enrolment`, ring.mail, { reason: why, by_mail: true }).then((answer) => {
      if (!screen.live()) {
        return;
      }
      const sent = answer.ok ? readMailed(answer.body) : null;
      if (sent === null) {
        refusedHere(answer);
        return;
      }
      ring.mail = keys();
      out.replaceChildren(
        make(
          "div",
          "panel",
          make(
            "p",
            "",
            `A link to set a password was sent to the account's address. It works for ${sent.validHours} hours; ` +
              "a new code replaces it. Nobody here sees the code.",
          ),
        ),
      );
      say("Enrolment link sent.");
    });
  });

  const move = (path: "disable" | "enable"): void => {
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    void change(`${base}/${path}`, ring.move, { reason: why }).then((answer) => {
      if (!screen.live()) {
        return;
      }
      if (!answer.ok) {
        refusedHere(answer);
        return;
      }
      if (path === "enable") {
        redraw("Account enabled.");
        return;
      }
      const ended = readDisabled(answer.body);
      const until = ended === null ? null : new Date(ended.accessTokensEndBy * 1000).toLocaleTimeString();
      redraw(
        ended === null || until === null
          ? "Account disabled."
          : `Account disabled: ${ended.sessions} sessions and ${ended.families} refresh families ended; access ` +
              `tokens it already holds stop working by ${until}.`,
      );
    });
  };

  const confirmPanel = make(
    "div",
    "confirm",
    make(
      "p",
      "",
      "Disable ",
      make("code", "", user.email),
      "? Its sessions end, its refresh tokens stop working, and every application it signed in to is told.",
    ),
  );
  confirmPanel.hidden = true;
  const stay = button("Keep it active", "secondary", () => {
    confirmPanel.hidden = true;
    disable.focus();
  });
  confirmPanel.append(
    make(
      "div",
      "actions",
      button("Disable the account", "danger", () => move("disable")),
      stay,
    ),
  );
  const disable = button("Disable account", "secondary", () => {
    if (reasonIn(reason.input, said) === null) {
      return;
    }
    confirmPanel.hidden = false;
    stay.focus();
  });
  const enable = button("Enable account", "secondary", () => move("enable"));

  const buttons = make("div", "actions", reveal, enrol, mail, user.status === "active" ? disable : enable);
  const title = make("h2", "", "Change this account");
  return make("section", "change-form", title, reason.row, said, buttons, confirmPanel, out);
}
