// What the clients view decides, kept apart from the document: the registrations page as the server answers it, and
// the registration a form describes. The form is checked for what the operator can fix here; the server reads every
// value again by its own types and refuses whatever this misses.

import { field, strings } from "./flow.ts";

/** The algorithms a confidential client may sign its assertions with, as the server names them. */
export const ALGORITHMS = ["EdDSA", "ES256"] as const;

/** The grants a client may register, as the server names them. */
export const GRANTS = ["authorization_code", "refresh_token", "client_credentials"] as const;

/** One registration as the console shows it. */
export interface Client {
  id: string;
  kind: "public" | "confidential";
  authMethod: string;
  assertionAlg: string | null;
  redirectUris: string[];
  scopeCeiling: string[];
  resources: string[];
  grantTypes: string[];
  dpop: boolean;
  keys: number;
  console: boolean;
}

/** A page of registrations and the cursor of the next one, when there is one. */
export interface ClientsPage {
  clients: Client[];
  next: string | null;
}

/** What the registration form holds. */
export interface ClientForm {
  id: string;
  confidential: boolean;
  algorithm: string;
  jwk: string;
  redirects: string;
  scopes: string;
  resources: string;
  grants: readonly string[];
  dpop: boolean;
}

/** The form field a refusal points at. */
export type FormField = "id" | "jwk" | "algorithm" | "redirects" | "scopes" | "grants";

/** The address of the registrations page after the cursor `after`. */
export function clientsPath(after: string | null): string {
  return after === null ? "api/clients" : `api/clients?${new URLSearchParams({ after }).toString()}`;
}

function readClient(value: unknown): Client | null {
  const id = field(value, "client_id");
  const kind = field(value, "kind");
  const authMethod = field(value, "auth_method");
  const assertionAlg = field(value, "assertion_alg");
  const redirectUris = strings(field(value, "redirect_uris"));
  const scopeCeiling = strings(field(value, "scope_ceiling"));
  const resources = strings(field(value, "resources"));
  const grantTypes = strings(field(value, "grant_types"));
  const dpop = field(value, "dpop_bound_access_tokens");
  const keys = field(value, "keys");
  const console = field(value, "console");
  if (
    typeof id !== "string" || id === "" || (kind !== "public" && kind !== "confidential")
    || typeof authMethod !== "string" || (assertionAlg !== null && typeof assertionAlg !== "string")
    || redirectUris === null || scopeCeiling === null || resources === null || grantTypes === null
    || typeof dpop !== "boolean" || typeof keys !== "number" || !Number.isSafeInteger(keys) || keys < 0
    || typeof console !== "boolean"
  ) {
    return null;
  }
  return { id, kind, authMethod, assertionAlg, redirectUris, scopeCeiling, resources, grantTypes, dpop, keys, console };
}

/** `GET api/clients`'s answer, or null when any part of it is not the shape the console knows. */
export function readClientsPage(body: unknown): ClientsPage | null {
  const listed = field(body, "clients");
  const next = field(body, "next");
  if (!Array.isArray(listed) || (next !== null && typeof next !== "string")) {
    return null;
  }
  const clients: Client[] = [];
  for (const value of listed) {
    const client = readClient(value);
    if (client === null) {
      return null;
    }
    clients.push(client);
  }
  return { clients, next };
}

/** One registration answered alone, as `POST api/clients` answers it. */
export function readRegistered(body: unknown): Client | null {
  return readClient(body);
}

/** The address of the one registration `id`. */
export function clientPath(id: string): string {
  return `api/clients/${encodeURIComponent(id)}`;
}

/** The address removing the registration `id`. */
export function removalPath(id: string): string {
  return `${clientPath(id)}/remove`;
}

/** A natural number field of `body`, or null. */
function count(body: unknown, key: string): number | null {
  const value = field(body, key);
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** How many users hold a grant to the one registration `GET api/clients/{id}` answers. */
export function readHolders(body: unknown): number | null {
  return count(body, "holders");
}

/** What ended with a removed client, and when the access tokens it already holds stop working. */
export function readRemoved(
  body: unknown,
): { clientId: string; consents: number; families: number; accessTokensEndBy: number } | null {
  const clientId = field(body, "client_id");
  const consents = count(body, "consents");
  const families = count(body, "families");
  const accessTokensEndBy = count(body, "access_tokens_end_by");
  if (typeof clientId !== "string" || clientId === "" || consents === null || families === null
    || accessTokensEndBy === null) {
    return null;
  }
  return { clientId, consents, families, accessTokensEndBy };
}

/** The values a list field holds: one per line or space, empty ones dropped. */
export function listOf(text: string): string[] {
  return text.split(/\s+/).filter((value) => value !== "");
}

/** Whether `id` is a client id the server can keep: 1 to 255 visible ASCII characters or spaces. */
function clientIdOf(id: string): boolean {
  return id.length >= 1 && id.length <= 255 && /^[\x20-\x7e]+$/.test(id);
}

/** The JWK `text` holds when it is one JSON object, else null. */
function jwkOf(text: string): object | null {
  try {
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** The request body `form` describes (without the reason), or the field to fix. */
export function registrationOf(form: ClientForm): { body: Record<string, unknown> } | { wrong: FormField } {
  const id = form.id.trim();
  if (!clientIdOf(id)) {
    return { wrong: "id" };
  }
  const redirects = listOf(form.redirects);
  const grants = GRANTS.filter((grant) => form.grants.includes(grant));
  // A public client's credentials are in every copy of it, so it never acts as itself; a code flow needs somewhere to
  // send its code.
  if (grants.length === 0 || (!form.confidential && grants.includes("client_credentials"))) {
    return { wrong: "grants" };
  }
  if (grants.includes("authorization_code") && redirects.length === 0) {
    return { wrong: "redirects" };
  }
  const shared = {
    client_id: id,
    redirect_uris: redirects,
    scope_ceiling: listOf(form.scopes),
    resources: listOf(form.resources),
  };
  if (!form.confidential) {
    return {
      body: { ...shared, auth_method: "none", grant_types: grants, dpop_bound_access_tokens: form.dpop },
    };
  }
  const jwk = jwkOf(form.jwk.trim());
  if (jwk === null) {
    return { wrong: "jwk" };
  }
  if (!ALGORITHMS.some((algorithm) => algorithm === form.algorithm)) {
    return { wrong: "algorithm" };
  }
  return {
    body: {
      ...shared,
      auth_method: "private_key_jwt",
      assertion_alg: form.algorithm,
      jwks: [jwk],
      grant_types: grants,
      dpop_bound_access_tokens: form.dpop,
    },
  };
}
