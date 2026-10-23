// The Mail view: every mail the server sends the company's users, with the wording it goes out with, and the changes
// to it. A change names the revision the operator saw, so the server refuses it when someone changed the wording
// meanwhile, and the server checks every wording against its mail's rules: the link a mail works by stays in it.

import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { changeRefusalText } from "./console-copy.ts";
import { type Screen, button, heading, labelled, make, show } from "./console-dom.ts";
import { type Answer, call, say } from "./dom.ts";
import { type Mail, mailBody, mailTitle, readMail, resetBody, ruleMessage } from "./mail-read.ts";

const PATH = "api/mail";

/** Say `text` in `said`, or leave it to `screen` when the session has ended. */
function sayIn(said: HTMLParagraphElement, text: string | null): void {
  if (text !== null) {
    said.textContent = text;
    said.hidden = false;
  }
}

/** `names` as placeholders written in braces. */
function braced(names: readonly string[]): string {
  return names.map((name) => `{${name}}`).join(", ");
}

/** What the wording may and must name, in the operator's words. */
function help(mail: Mail): HTMLParagraphElement {
  const may =
    mail.placeholders.length === 0 ? "This mail fills in nothing." : `It may use ${braced(mail.placeholders)}.`;
  const must = mail.required.length === 0 ? "" : ` It must keep ${braced(mail.required)}.`;
  return make("p", "muted", `${may}${must} Write {{ or }} for a brace itself. Plain text only.`);
}

/** The form changing one kind's wording at `mail.revision`; `redraw` shows the view afresh with a message. */
function mailForm(screen: Screen, mail: Mail, redraw: (message: string) => void): HTMLDetailsElement {
  const keyFor = keys();
  const id = `mail-${mail.kind}`;
  const subject = make("input", "");
  subject.type = "text";
  subject.value = mail.subject;
  subject.maxLength = 200;
  subject.autocomplete = "off";
  const text = make("textarea", "mono");
  text.id = `${id}-text`;
  text.value = mail.text;
  text.rows = 8;
  text.maxLength = 10000;
  text.spellcheck = true;
  const textLabel = make("label", "", "Text");
  textLabel.htmlFor = text.id;
  const reason = reasonField(`${id}-reason`);
  const said = notice();
  const title = mailTitle(mail.kind);
  const answered = (done: string) => (answer: Answer): void => {
    if (!screen.live()) {
      return;
    }
    if (answer.ok && readMail({ mail: [answer.body] }) !== null) {
      redraw(done);
      return;
    }
    if (answer.status === 409) {
      redraw(changeRefusalText("changed_meanwhile"));
      return;
    }
    const rule = ruleMessage(answer.body);
    if (rule !== null) {
      text.setAttribute("aria-invalid", "true");
      sayIn(said, `The server keeps this mail as it was: ${rule}.`);
      return;
    }
    const unread = "The server answered in a shape the console cannot read.";
    sayIn(said, answer.ok ? unread : refusedText(screen, answer, title));
  };
  const save = button("Save the wording", "primary", () => {
    said.hidden = true;
    text.removeAttribute("aria-invalid");
    const why = reasonIn(reason.input, said);
    if (why !== null) {
      const body = mailBody(mail.revision, subject.value, text.value, why);
      void change(`${PATH}/${mail.kind}`, keyFor, body, "PUT").then(
        answered(`${title}: the company's wording is saved. The next mail goes out with it.`),
      );
    }
  });
  const actions = make("div", "actions", save);
  if (mail.own) {
    actions.append(
      button("Use the default", "secondary", () => {
        said.hidden = true;
        const why = reasonIn(reason.input, said);
        if (why !== null) {
          void change(`${PATH}/${mail.kind}/reset`, keyFor, resetBody(mail.revision, why)).then(
            answered(`${title}: the default wording is back. The next mail goes out with it.`),
          );
        }
      }),
    );
  }
  const summary = make(
    "summary",
    "",
    make("span", "", title),
    " ",
    make("span", "pill", mail.own ? "Company wording" : "Default"),
  );
  return make(
    "details",
    "mail-kind",
    summary,
    make(
      "div",
      "change-form",
      labelled(`${id}-subject`, "Subject", subject),
      make("div", "field", textLabel, text),
      help(mail),
      reason.row,
      said,
      actions,
    ),
  );
}

/** The Mail view, with `message` said once it is drawn. */
export async function mailView(screen: Screen, message = ""): Promise<void> {
  say("Loading the mail.");
  const answer = await call("GET", PATH);
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Mail", answer, "The mail");
    return;
  }
  const mail = readMail(answer.body);
  if (mail === null) {
    unreadable(screen, "Mail");
    return;
  }
  const redraw = (said: string): void => void mailView(screen, said);
  show(
    screen.view,
    heading("Mail"),
    make(
      "p",
      "lead",
      "The words of each mail the server sends the company's users. Who gets a mail, and when, stays the server's.",
    ),
    ...mail.map((kind) => mailForm(screen, kind, redraw)),
  );
  say(message);
}
