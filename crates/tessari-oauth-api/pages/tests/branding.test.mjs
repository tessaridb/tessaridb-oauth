// What the console's Branding view reads and says: the brand as the server answers it, with the revision a change
// must name, and the server's refusals in the operator's words.
import assert from "node:assert/strict";
import { test } from "node:test";

import { brandingBody, readBranding } from "../src/branding-read.ts";
import { brandRefusalText } from "../src/console-copy.ts";
import { offered, route } from "../src/console-read.ts";

test("the brand is read as the server answers it, every value or none", () => {
  assert.deepEqual(
    readBranding({
      name: "Acme",
      accent: "#1f4fd8",
      support_url: "https://help.acme.example/",
      privacy_url: null,
      logo: 1800000000,
      revision: 3,
    }),
    {
      name: "Acme",
      accent: "#1f4fd8",
      supportUrl: "https://help.acme.example/",
      privacyUrl: null,
      logo: 1800000000,
      revision: 3,
    },
  );
  assert.deepEqual(
    readBranding({ name: null, accent: null, support_url: null, privacy_url: null, logo: null, revision: 0 }),
    { name: null, accent: null, supportUrl: null, privacyUrl: null, logo: null, revision: 0 },
  );
});

test("an answer of another shape is not read", () => {
  assert.equal(readBranding(null), null);
  assert.equal(readBranding({ name: "Acme", accent: "#1f4fd8", logo: null }), null, "no revision");
  const none = { name: null, accent: null, support_url: null, privacy_url: null, logo: null, revision: 0 };
  assert.equal(readBranding({ ...none, name: 7 }), null);
  assert.equal(readBranding({ ...none, revision: -1 }), null);
  assert.equal(readBranding({ ...none, logo: "1" }), null);
});

test("a change names the revision it replaces and leaves out an empty link", () => {
  assert.deepEqual(brandingBody(2, " Acme ", "#1F4FD8", "", "https://acme.example/privacy", "rebrand"), {
    revision: 2,
    name: " Acme ",
    accent: "#1F4FD8",
    privacy_url: "https://acme.example/privacy",
    reason: "rebrand",
  });
});

test("every brand refusal says what to change", () => {
  for (const code of [
    "brand_name_invalid",
    "accent_invalid",
    "accent_low_contrast",
    "link_invalid",
    "logo_too_large",
    "logo_not_png",
    "logo_unreadable",
    "logo_too_wide",
    "no_logo",
  ]) {
    const text = brandRefusalText(code);
    assert.notEqual(text, brandRefusalText("something_else"), code);
    assert.doesNotMatch(text, /_/, `${code}: no code reaches the operator`);
  }
});

test("Branding is its own view, offered to policy operators", () => {
  assert.deepEqual(route("#/branding"), { kind: "branding" });
  assert.ok(offered(["policy"]).includes("branding"));
  assert.ok(!offered(["users", "clients", "audit"]).includes("branding"));
});
