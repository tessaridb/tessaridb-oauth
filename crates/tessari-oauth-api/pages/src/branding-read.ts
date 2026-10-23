// What the Branding view reads and sends, kept apart from the document: the brand as `GET api/branding` answers it,
// with the revision a change must name, and the body of a change, which leaves out a link left empty.

import { field } from "./flow.ts";

/** The company's brand; every value null and the revision 0 when none is set. */
export interface Branding {
  name: string | null;
  accent: string | null;
  supportUrl: string | null;
  privacyUrl: string | null;
  /** Unix seconds of the logo's upload. */
  logo: number | null;
  revision: number;
}

function text(value: unknown): string | null | undefined {
  return value === null || typeof value === "string" ? value : undefined;
}

function whole(value: unknown): number | null | undefined {
  return value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) ? value : undefined;
}

/** `GET api/branding`'s answer, or null for any other shape. */
export function readBranding(body: unknown): Branding | null {
  const name = text(field(body, "name"));
  const accent = text(field(body, "accent"));
  const supportUrl = text(field(body, "support_url"));
  const privacyUrl = text(field(body, "privacy_url"));
  const logo = whole(field(body, "logo"));
  const revision = whole(field(body, "revision"));
  if (
    name === undefined ||
    accent === undefined ||
    supportUrl === undefined ||
    privacyUrl === undefined ||
    logo === undefined ||
    revision === undefined ||
    revision === null
  ) {
    return null;
  }
  return { name, accent, supportUrl, privacyUrl, logo, revision };
}

/** The body of a change to the brand at `revision`; an empty link is left out, so the brand has none. */
export function brandingBody(
  revision: number,
  name: string,
  accent: string,
  supportUrl: string,
  privacyUrl: string,
  reason: string,
): Record<string, unknown> {
  return {
    revision,
    name,
    accent,
    ...(supportUrl === "" ? {} : { support_url: supportUrl }),
    ...(privacyUrl === "" ? {} : { privacy_url: privacyUrl }),
    reason,
  };
}
