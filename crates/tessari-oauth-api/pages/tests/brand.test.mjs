// What the public pages take from a company's brand: the name as text, a link only when it is an https address,
// and the logo's address only when the server says one was uploaded.
import assert from "node:assert/strict";
import { test } from "node:test";

import { logoAddress, readBrand } from "../src/brand-read.ts";

test("a brand the server set is read as it was set", () => {
  const brand = readBrand({
    name: "Acme <b>Bank</b>",
    support: "https://help.acme.example/",
    privacy: "https://acme.example/privacy",
    logo: 1800000000,
  });
  assert.deepEqual(brand, {
    name: "Acme <b>Bank</b>",
    support: "https://help.acme.example/",
    privacy: "https://acme.example/privacy",
    logo: 1800000000,
  });
  assert.equal(logoAddress(1800000000), "assets/logo.png?v=1800000000");
});

test("no brand leaves every field empty, so the pages keep their own", () => {
  assert.deepEqual(readBrand({ name: null, support: null, privacy: null, logo: null }), {
    name: null,
    support: null,
    privacy: null,
    logo: null,
  });
  assert.deepEqual(readBrand(null), { name: null, support: null, privacy: null, logo: null });
});

test("a link that is not an https address is never offered", () => {
  const refused = ["javascript:alert(1)", "http://acme.example/", "//acme.example/", "data:text/html,x", " https://x/"];
  for (const link of refused) {
    const brand = readBrand({ name: "Acme", support: link, privacy: link, logo: null });
    assert.equal(brand.support, null, link);
    assert.equal(brand.privacy, null, link);
  }
});

test("a field of another kind is dropped, not shown", () => {
  const brand = readBrand({ name: 7, support: ["https://x/"], privacy: {}, logo: "1" });
  assert.deepEqual(brand, { name: null, support: null, privacy: null, logo: null });
  assert.equal(readBrand({ name: "", support: null, privacy: null, logo: -1 }).logo, null);
  assert.equal(readBrand({ name: "", support: null, privacy: null, logo: 1.5 }).logo, null);
  assert.equal(readBrand({ name: "", support: null, privacy: null, logo: null }).name, null);
});
