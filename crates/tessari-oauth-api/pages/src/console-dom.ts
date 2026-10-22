// The console's views are built from elements, never from markup text, so nothing an API answers is ever read as
// HTML. These are the few shapes every view is made of.

/** An element `tag` with `className` and the text or children given. */
export function make<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const made = document.createElement(tag);
  if (className !== "") {
    made.className = className;
  }
  made.append(...children);
  return made;
}

/** A link to `href` reading `text`. */
export function link(href: string, text: string, className = ""): HTMLAnchorElement {
  const made = make("a", className, text);
  made.href = href;
  return made;
}

/** A button reading `text` that runs `then` when pressed. */
export function button(text: string, className: string, then: () => void): HTMLButtonElement {
  const made = make("button", className, text);
  made.type = "button";
  made.addEventListener("click", then);
  return made;
}

/** A view's heading, focused so a keyboard or screen-reader user lands on the new view. */
export function heading(text: string): HTMLHeadingElement {
  const made = make("h1", "view-title", text);
  made.tabIndex = -1;
  return made;
}

/** Replace what `view` shows with `children`, and move focus to its heading when it has one. */
export function show(view: HTMLElement, ...children: Node[]): void {
  view.replaceChildren(...children);
  view.querySelector<HTMLHeadingElement>(".view-title")?.focus();
}

/** Where a view draws, whether its answer is still wanted, and how it hands over to signing in. */
export interface Screen {
  view: HTMLElement;
  /** False once the operator has moved to another view, so a late answer paints nothing. */
  live(): boolean;
  signedOut(): void;
}

/** A labelled field: the label, then the input, wired together by `id`. */
export function labelled(id: string, text: string, input: HTMLInputElement): HTMLDivElement {
  const label = make("label", "", text);
  label.htmlFor = id;
  input.id = id;
  return make("div", "field", label, input);
}
