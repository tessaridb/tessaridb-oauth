// What the Keys view reads, kept apart from the document: each signing key with the state the rotation rule gives
// it, and the answers to making a successor and to withdrawing a key.

import { field } from "./flow.ts";

/** Where a key is in its life, as the server names it. */
export type KeyState = "signing" | "waiting" | "previous" | "retiring" | "withdrawn";

const STATES: readonly KeyState[] = ["signing", "waiting", "previous", "retiring", "withdrawn"];

/** One signing key; `signsFrom` is set only while it waits to sign. */
export interface SigningKey {
  kid: string;
  algorithm: string;
  /** Unix seconds of when it was made and published. */
  createdAt: number;
  state: KeyState;
  signsFrom: number | null;
}

/** A successor made, and when it signs. */
export interface Rotated {
  kid: string;
  signsFrom: number;
}

/** A key withdrawn, and the key made to replace it when none other could sign. */
export interface Withdrawn {
  withdrawn: string;
  replacement: string | null;
}

function name(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

function seconds(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function readKey(item: unknown): SigningKey | null {
  const kid = name(field(item, "kid"));
  const algorithm = name(field(item, "algorithm"));
  const createdAt = seconds(field(item, "created_at"));
  const state = STATES.find((known) => known === field(item, "state"));
  const sent = field(item, "signs_from");
  const signsFrom = sent === null ? null : seconds(sent);
  if (kid === null || algorithm === null || createdAt === null || state === undefined) {
    return null;
  }
  if (sent !== null && signsFrom === null) {
    return null;
  }
  return { kid, algorithm, createdAt, state, signsFrom };
}

/** `GET api/keys`'s answer, oldest first, or null for any other shape. */
export function readKeys(body: unknown): SigningKey[] | null {
  const items = field(body, "keys");
  if (!Array.isArray(items)) {
    return null;
  }
  const keys = items.map(readKey);
  return keys.every((key): key is SigningKey => key !== null) ? keys : null;
}

/** The answer to `POST api/keys/rotate`, or null for any other shape. */
export function readRotated(body: unknown): Rotated | null {
  const kid = name(field(body, "kid"));
  const signsFrom = seconds(field(body, "signs_from"));
  return kid === null || signsFrom === null ? null : { kid, signsFrom };
}

/** The answer to `POST api/keys/<kid>/withdraw`, or null for any other shape. */
export function readWithdrawn(body: unknown): Withdrawn | null {
  const withdrawn = name(field(body, "withdrawn"));
  const sent = field(body, "replacement");
  const replacement = sent === null ? null : name(sent);
  if (withdrawn === null || (sent !== null && replacement === null)) {
    return null;
  }
  return { withdrawn, replacement };
}
