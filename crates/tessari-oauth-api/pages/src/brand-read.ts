// What the public pages take from `assets/brand.json`, kept apart from the document so it can be tested without a
// browser. The server sends only values it validated, and the page still reads each one as unknown: a name is text
// to set as text, a link is offered only when it is an https address, and the logo is fetched only when one exists.

import { field } from "./flow.ts";

/** A company's brand as the pages show it; null where the company set nothing. */
export interface Brand {
  name: string | null;
  support: string | null;
  privacy: string | null;
  /** Unix seconds of the logo's upload. */
  logo: number | null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

function link(value: unknown): string | null {
  return typeof value === "string" && value.startsWith("https://") ? value : null;
}

function seconds(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** The brand in `body`, the answer of `assets/brand.json`. */
export function readBrand(body: unknown): Brand {
  return {
    name: text(field(body, "name")),
    support: link(field(body, "support")),
    privacy: link(field(body, "privacy")),
    logo: seconds(field(body, "logo")),
  };
}

/** The logo's address under the page's `assets` path, carrying its upload time so a new logo is fetched rather than
 * a cached one. */
export function logoAddress(uploaded: number, assets = "assets/"): string {
  return `${assets}logo.png?v=${uploaded}`;
}
