// The changes an operator holding `users` makes to accounts. Every change carries a reason and an Idempotency-Key
// made once per form, so a double press is one change. Disabling ends what the account holds elsewhere, so it is
// confirmed with the account named; enabling is undone by disabling and is not. Showing an address whole is
// recorded with the reason, and an enrolment code is shown once and never kept by the page.

import { readRefusal } from "./console-read.ts";
import { changeRefusalText, refusalText } from "./console-copy.ts";
import { type Screen, button, labelled, make } from "./console-dom.ts";
import { type Answer, call, say } from "./dom.ts";
import { field } from "./flow.ts";
import { type User } from "./users-read.ts";
import { keyring, readDisabled, readIssued, readOpened, readRevealed, reasonOf } from "./users-change.ts";

/** A form's keyring: one key per distinct body sent. */
function keys(): (body: Record<string, string>) => string {
  return keyring(() => crypto.randomUUID());
}

/** POST the change `body` to `path` under the key `keyFor` gives that body. */
function change(path: string, keyFor: (body: Record<string, string>) => string, body: Record<string, string>) {
  return call("POST", path, body, { "idempotency-key": keyFor(body) });
}

/** The words for a refused change `answer`, or null when the session has ended and `screen` signs out instead. */
function refusedText(screen: Screen, answer: Answer): string | null {
  const refusal = readRefusal(answer.status, answer.body, answer.retryAfter);
  if (refusal.kind === "signed_out") {
    screen.signedOut();
    return null;
  }
  if (refusal.kind === "refused") {
    return changeRefusalText(refusal.code);
  }
  const code = field(answer.body, "code");
  return refusal.kind === "not_found" && code === "user_not_found"
    ? "This account is no longer in this company."
    : refusalText(refusal, "This account");
}

/** The reason field of a change form. */
function reasonField(id: string): { input: HTMLInputElement; row: HTMLDivElement } {
  const input = make("input", "");
  input.type = "text";
  input.required = true;
  input.maxLength = 500;
  input.autocomplete = "off";
  return { input, row: labelled(id, "Reason (recorded with the change)", input) };
}

/** The reason typed into `input`, or null after saying what is missing in `notice`. */
function reasonIn(input: HTMLInputElement, notice: HTMLParagraphElement): string | null {
  const reason = reasonOf(input.value);
  if (reason === null) {
    notice.textContent = changeRefusalText("reason_required");
    notice.hidden = false;
    input.setAttribute("aria-invalid", "true");
    input.focus();
    return null;
  }
  input.removeAttribute("aria-invalid");
  return reason;
}

/** A notice paragraph, hidden until it has something to say. */
function notice(): HTMLParagraphElement {
  const made = make("p", "notice");
  made.setAttribute("role", "alert");
  made.hidden = true;
  return made;
}

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
      const text = answer.ok ? "The server answered in a shape the console cannot read." : refusedText(screen, answer);
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
  const ring = { reveal: keys(), enrol: keys(), move: keys() };

  const refusedHere = (answer: Answer): void => {
    const text = refusedText(screen, answer);
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

  const buttons = make("div", "actions", reveal, enrol, user.status === "active" ? disable : enable);
  const title = make("h2", "", "Change this account");
  return make("section", "change-form", title, reason.row, said, buttons, confirmPanel, out);
}
