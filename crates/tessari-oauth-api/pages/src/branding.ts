// The Branding view: the company's name, colour, links and logo as its sign-in, consent and account pages show
// them, and the changes to them. A change names the revision the operator saw, so the server refuses it when someone
// changed the brand meanwhile; the logo is uploaded as the PNG file chosen, which the server re-encodes.

import { brandingBody, readBranding, type Branding } from "./branding-read.ts";
import { brandRefusalText } from "./console-copy.ts";
import { change, keys, notice, reasonField, reasonIn, refusedOn, refusedText, unreadable } from "./console-change.ts";
import { type Screen, button, heading, labelled, make, show } from "./console-dom.ts";
import { when } from "./copy.ts";
import { type Answer, call, say } from "./dom.ts";
import { toBase64url } from "./flow.ts";

const PATH = "api/branding";
/** The largest logo the server keeps; a larger file is refused here rather than sent. */
const LOGO_MAX_BYTES = 256 * 1024;
const COLOUR = /^#[0-9a-fA-F]{6}$/;

/** A text input of `type` holding `value`. */
function input(type: "text" | "url", value: string | null, className = ""): HTMLInputElement {
  const made = make("input", className);
  made.type = type;
  made.value = value ?? "";
  made.autocomplete = "off";
  made.spellcheck = false;
  return made;
}

/** A square showing `colour`, set through the style object so the console's policy needs no inline style. */
function swatch(colour: string | null): HTMLSpanElement {
  const made = make("span", "swatch");
  made.setAttribute("aria-hidden", "true");
  made.style.backgroundColor = colour ?? "";
  made.hidden = colour === null;
  return made;
}

/** Say `text` in `said`, or leave it to `screen` when the session has ended. */
function sayIn(said: HTMLParagraphElement, text: string | null): void {
  if (text !== null) {
    said.textContent = text;
    said.hidden = false;
  }
}

/** What the brand is now, as facts. */
function facts(brand: Branding): HTMLDListElement {
  const fact = (term: string, ...value: (Node | string)[]): Node[] => [make("dt", "", term), make("dd", "", ...value)];
  return make(
    "dl",
    "facts",
    ...fact("Name", brand.name ?? "Not set: the pages say TessariDB"),
    ...fact(
      "Colour",
      ...(brand.accent === null
        ? ["Not set: the house colour"]
        : [swatch(brand.accent), " ", make("code", "", brand.accent)]),
    ),
    ...fact("Help link", brand.supportUrl ?? "None"),
    ...fact("Privacy link", brand.privacyUrl ?? "None"),
    ...fact("Logo", brand.logo === null ? "None: the pages show the product mark" : `Uploaded ${when(brand.logo)}`),
  );
}

/** The form replacing the brand at `brand.revision`; `redraw` shows the view afresh with a message. */
function brandForm(screen: Screen, brand: Branding, redraw: (message: string) => void): HTMLElement {
  const keyFor = keys();
  const name = input("text", brand.name);
  name.maxLength = 64;
  const accent = input("text", brand.accent, "mono");
  accent.maxLength = 7;
  accent.placeholder = "#1f4fd8";
  const preview = swatch(brand.accent);
  accent.addEventListener("input", () => {
    const valid = COLOUR.test(accent.value);
    preview.style.backgroundColor = valid ? accent.value : "";
    preview.hidden = !valid;
  });
  const support = input("url", brand.supportUrl);
  const privacy = input("url", brand.privacyUrl);
  const reason = reasonField("brand-reason");
  const said = notice();
  const colourRow = labelled("brand-accent", "Colour of buttons and links (white text must be readable on it)", accent);
  colourRow.append(preview);
  const save = button("Save the brand", "primary", () => {
    said.hidden = true;
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    const links = [support.value.trim(), privacy.value.trim()] as const;
    const body = brandingBody(brand.revision, name.value, accent.value, ...links, why);
    void change(PATH, keyFor, body, "PUT").then((answer) => {
      if (!screen.live()) {
        return;
      }
      if (answer.ok && readBranding(answer.body) !== null) {
        redraw("The brand is saved. The sign-in, consent and account pages show it now.");
        return;
      }
      if (answer.status === 409) {
        redraw(brandRefusalText("changed_meanwhile"));
        return;
      }
      const unread = "The server answered in a shape the console cannot read.";
      sayIn(said, answer.ok ? unread : refusedText(screen, answer, "The brand", brandRefusalText));
    });
  });
  return make(
    "section",
    "change-form",
    make("h2", "", "Change it"),
    labelled("brand-name", "Name", name),
    colourRow,
    labelled("brand-support", "Help link (https, optional)", support),
    labelled("brand-privacy", "Privacy link (https, optional)", privacy),
    reason.row,
    said,
    make("div", "actions", save),
  );
}

/** The form uploading or removing the logo; `redraw` shows the view afresh with a message. */
function logoForm(screen: Screen, brand: Branding, redraw: (message: string) => void): HTMLElement {
  const keyFor = keys();
  const file = make("input", "");
  file.type = "file";
  file.accept = "image/png";
  const reason = reasonField("logo-reason");
  const said = notice();
  const answered = (text: string) => (answer: Answer): void => {
    if (!screen.live()) {
      return;
    }
    if (answer.ok) {
      redraw(text);
      return;
    }
    sayIn(said, refusedText(screen, answer, "The logo", brandRefusalText));
  };
  const upload = button("Upload the logo", "primary", () => {
    said.hidden = true;
    const chosen = file.files?.[0];
    if (chosen === undefined) {
      sayIn(said, "Choose a PNG file first.");
      file.focus();
      return;
    }
    if (chosen.size > LOGO_MAX_BYTES) {
      sayIn(said, brandRefusalText("logo_too_large"));
      return;
    }
    const why = reasonIn(reason.input, said);
    if (why === null) {
      return;
    }
    void chosen.arrayBuffer().then((bytes) => {
      const body = { png: toBase64url(new Uint8Array(bytes)), reason: why };
      void change(`${PATH}/logo`, keyFor, body, "PUT").then(answered("The logo is uploaded. The pages show it now."));
    });
  });
  const actions = make("div", "actions", upload);
  if (brand.logo !== null) {
    actions.append(
      button("Remove the logo", "secondary", () => {
        said.hidden = true;
        const why = reasonIn(reason.input, said);
        if (why !== null) {
          void change(`${PATH}/logo/remove`, keyFor, { reason: why }).then(
            answered("The logo is removed. The pages show the product mark again."),
          );
        }
      }),
    );
  }
  const fileLabel = make("label", "", "PNG file, at most 256 KiB and 512 by 512 pixels");
  file.id = "logo-file";
  fileLabel.htmlFor = file.id;
  const fileRow = make("div", "field", fileLabel, file);
  return make("section", "change-form", make("h2", "", "Logo"), fileRow, reason.row, said, actions);
}

/** The Branding view, with `message` said once it is drawn. */
export async function brandingView(screen: Screen, message = ""): Promise<void> {
  say("Loading the brand.");
  const answer = await call("GET", PATH);
  if (!screen.live()) {
    return;
  }
  if (!answer.ok) {
    refusedOn(screen, "Branding", answer, "The brand");
    return;
  }
  const brand = readBranding(answer.body);
  if (brand === null) {
    unreadable(screen, "Branding");
    return;
  }
  const redraw = (said: string): void => void brandingView(screen, said);
  show(
    screen.view,
    heading("Branding"),
    make("p", "lead", "How the company's sign-in, consent and account pages look. Nothing here changes what they do."),
    facts(brand),
    brandForm(screen, brand, redraw),
    logoForm(screen, brand, redraw),
  );
  say(message);
}
