// The little the pages need from the document and the network, typed: an element looked up is checked to be the
// kind the page expects, and a call to the API answers its status, its body and its wait, never throws for a
// refusal.

/** The element `id`, which the page's own markup guarantees is a `kind`. */
export function element<T extends HTMLElement>(id: string, kind: new () => T): T {
  const found = document.getElementById(id);
  if (!(found instanceof kind)) {
    throw new Error(`the page has no ${kind.name} #${id}`);
  }
  return found;
}

/** What the API answered. */
export interface Answer {
  ok: boolean;
  status: number;
  body: unknown;
  retryAfter: string | null;
}

/** Call `path` with `method` and, when given, `body` as JSON; a network failure answers as the server failing. */
export async function call(method: "GET" | "POST", path: string, body?: unknown): Promise<Answer> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: { accept: "application/json", "content-type": "application/json" },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  try {
    const response = await fetch(path, init);
    const text = await response.text();
    let parsed: unknown = null;
    try {
      parsed = text === "" ? null : JSON.parse(text);
    } catch {
      parsed = null;
    }
    return { ok: response.ok, status: response.status, body: parsed, retryAfter: response.headers.get("retry-after") };
  } catch {
    return { ok: false, status: 0, body: null, retryAfter: null };
  }
}

/** Show `text` as the field's error, wired for assistive technology, or clear it when `text` is null. */
export function fieldError(input: HTMLInputElement, text: string | null): void {
  const error = element(`${input.id}-error`, HTMLParagraphElement);
  error.textContent = text ?? "";
  error.hidden = text === null;
  if (text === null) {
    input.removeAttribute("aria-invalid");
  } else {
    input.setAttribute("aria-invalid", "true");
    input.focus();
  }
}

/** Say `text` in the page's status line, which assistive technology announces. */
export function say(text: string): void {
  element("status", HTMLParagraphElement).textContent = text;
}
