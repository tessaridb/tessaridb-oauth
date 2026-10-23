// The company's brand on a public page: its name in the header, its logo in place of the product mark, and its
// support and privacy links under the card. The name is set as text and a link only from an https address, so
// nothing a company supplies becomes markup; when the brand cannot be read the page keeps the product's own.

import { logoAddress, readBrand } from "./brand-read.ts";
import { call, element } from "./dom.ts";

function offer(id: string, address: string | null): boolean {
  const anchor = element(id, HTMLAnchorElement);
  if (address !== null) {
    anchor.href = address;
  }
  anchor.hidden = address === null;
  return address !== null;
}

/** Show the brand of the company this page belongs to. */
export async function showBrand(): Promise<void> {
  const answer = await call("GET", "assets/brand.json");
  if (!answer.ok) {
    return;
  }
  const brand = readBrand(answer.body);
  if (brand.name !== null) {
    element("brand-name", HTMLSpanElement).textContent = brand.name;
  }
  if (brand.logo !== null) {
    element("brand-logo", HTMLImageElement).src = logoAddress(brand.logo);
  }
  const support = offer("brand-support", brand.support);
  const privacy = offer("brand-privacy", brand.privacy);
  element("brand-links", HTMLParagraphElement).hidden = !support && !privacy;
}
