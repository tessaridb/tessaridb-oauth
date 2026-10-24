// The consent page. It asks what the pending authorization wants that the signed-in user has not yet granted,
// shows it, and sends the user's decision; the answer to the decision is where the browser goes next.

import { showBrand } from "./brand.ts";
import { TEXT, describeScope, refusalText } from "./copy.ts";
import { call, element, say } from "./dom.ts";
import { apiBase, readDelta, readRedirect, refusal } from "./flow.ts";

const request = element("request", HTMLDivElement);
const allow = element("allow", HTMLButtonElement);
const deny = element("deny", HTMLButtonElement);

/** Fill the list `id` with one item per entry of `items`. */
function list(id: string, items: readonly string[]): void {
  const target = element(id, HTMLUListElement);
  target.replaceChildren(
    ...items.map((item) => {
      const entry = document.createElement("li");
      entry.textContent = item;
      return entry;
    }),
  );
}

async function decide(base: string, interaction: string, decision: "allow" | "deny"): Promise<void> {
  allow.disabled = true;
  deny.disabled = true;
  const answer = await call("POST", `${base}/consent`, { interaction, decision });
  const target = answer.ok ? readRedirect(answer.body) : null;
  if (target !== null) {
    request.hidden = true;
    say(decision === "allow" ? TEXT.allowed : TEXT.denied);
    location.assign(target);
    return;
  }
  allow.disabled = false;
  deny.disabled = false;
  const refused = answer.ok ? { kind: "retry" as const } : refusal(answer.status, answer.body, answer.retryAfter);
  if (refused.kind === "expired") {
    request.hidden = true;
  }
  say(refusalText(refused));
}

async function main(): Promise<void> {
  const base = apiBase(location.pathname, "consent");
  const interaction = new URLSearchParams(location.search).get("interaction");
  if (base === null || interaction === null || interaction === "") {
    say(TEXT.missing);
    return;
  }
  const asked = await call("GET", `${base}/consent?${new URLSearchParams({ interaction }).toString()}`);
  const delta = asked.ok ? readDelta(asked.body) : null;
  if (delta === null) {
    say(refusalText(asked.ok ? { kind: "retry" } : refusal(asked.status, asked.body, asked.retryAfter)));
    return;
  }
  element("client", HTMLElement).textContent = delta.clientId;
  list("scopes", delta.scopes.length === 0 ? [TEXT.consentNothing] : delta.scopes.map(describeScope));
  list("resources", delta.resources);
  element("resources-block", HTMLDivElement).hidden = delta.resources.length === 0;
  allow.addEventListener("click", () => void decide(base, interaction, "allow"));
  deny.addEventListener("click", () => void decide(base, interaction, "deny"));
  request.hidden = false;
  say("");
  allow.focus();
}

void showBrand();
void main();
