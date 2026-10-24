// The companies view's decisions, without a browser: the directory page as the server answers it, the id and name a
// new company may have, the cursor in the address, and what each refused change tells the operator.
import assert from "node:assert/strict";
import { test } from "node:test";

import { route } from "../src/console-read.ts";
import { companyRefusalText } from "../src/console-copy.ts";
import { companiesPath, companyIdOf, companyNameOf, readCompaniesPage, readCompany } from "../src/companies-read.ts";

const acme = { id: "acme", name: "Acme Ltd", status: "active", created_at: 1761100000, created_by: "user-1" };

test("a directory page is read with its cursor, and a company of an unknown status is not", () => {
  assert.deepEqual(readCompaniesPage({ companies: [acme], next: "acme" }), {
    companies: [{ id: "acme", name: "Acme Ltd", status: "active", createdAt: 1761100000, createdBy: "user-1" }],
    next: "acme",
  });
  assert.equal(readCompaniesPage({ companies: [{ ...acme, status: "gone" }], next: null }), null);
  assert.equal(readCompaniesPage({ companies: [{ ...acme, created_at: "x" }], next: null }), null);
  assert.equal(readCompaniesPage({ next: null }), null);
  assert.equal(readCompany({ ...acme, status: "provisioning" })?.status, "provisioning");
});

test("a company id is 1 to 63 lowercase letters, digits and inner hyphens, as the server reads it", () => {
  assert.equal(companyIdOf(" north-wind "), "north-wind");
  assert.equal(companyIdOf("a".repeat(63)), "a".repeat(63));
  assert.equal(companyIdOf("a".repeat(64)), null);
  assert.equal(companyIdOf("North"), null);
  assert.equal(companyIdOf("-acme"), null);
  assert.equal(companyIdOf("acme-"), null);
  assert.equal(companyIdOf("ac me"), null);
  assert.equal(companyIdOf(""), null);
});

test("a company name is 1 to 100 characters after trimming, with no control character", () => {
  assert.equal(companyNameOf("  Acme Ltd "), "Acme Ltd");
  assert.equal(companyNameOf("é".repeat(100)), "é".repeat(100));
  assert.equal(companyNameOf("x".repeat(101)), null);
  assert.equal(companyNameOf("Acme\u0007"), null);
  assert.equal(companyNameOf("   "), null);
});

test("the directory follows the cursor in the address", () => {
  assert.equal(companiesPath(null), "api/companies");
  assert.equal(companiesPath("acme"), "api/companies?after=acme");
  assert.deepEqual(route("#/companies?after=acme"), { kind: "companies", after: "acme" });
  assert.deepEqual(route("#/companies"), { kind: "companies", after: null });
});

test("each refused company change says what happened in words, not its code", () => {
  for (const code of ["company_taken", "system_company", "changed_meanwhile"]) {
    const text = companyRefusalText(code);
    assert.notEqual(text, companyRefusalText("something-else"), code);
    assert.ok(!text.includes(code), `${code} is said in words`);
  }
  assert.equal(companyRefusalText("reason_required"), "Say why, in 1 to 500 characters.");
});
