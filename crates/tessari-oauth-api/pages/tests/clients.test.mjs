// The clients view's decisions, without a browser: the registrations page as the server answers it, the cursor in the
// address, the registration a form describes, and what each refused registration tells the operator.
import assert from "node:assert/strict";
import { test } from "node:test";

import { route } from "../src/console-read.ts";
import { clientRefusalText, clientRemovalRefusalText } from "../src/console-copy.ts";
import {
  clientPath,
  clientsPath,
  listOf,
  readClientsPage,
  readHolders,
  readRemoved,
  registrationOf,
  removalPath,
} from "../src/clients-read.ts";

const portal = {
  client_id: "portal",
  kind: "public",
  auth_method: "none",
  assertion_alg: null,
  redirect_uris: ["https://app.example/cb"],
  post_logout_redirect_uris: [],
  backchannel_logout_uri: null,
  scope_ceiling: ["openid", "orders:read"],
  resources: [],
  grant_types: ["authorization_code", "refresh_token"],
  dpop_bound_access_tokens: false,
  keys: 0,
  sector: null,
  console: false,
};

test("a registrations page is read whole with its cursor, and any part of another shape makes it unreadable", () => {
  assert.deepEqual(readClientsPage({ clients: [portal], next: "portal" }), {
    clients: [
      {
        id: "portal",
        kind: "public",
        authMethod: "none",
        assertionAlg: null,
        redirectUris: ["https://app.example/cb"],
        scopeCeiling: ["openid", "orders:read"],
        resources: [],
        grantTypes: ["authorization_code", "refresh_token"],
        dpop: false,
        keys: 0,
        sector: null,
        console: false,
      },
    ],
    next: "portal",
  });
  assert.equal(readClientsPage({ clients: [{ ...portal, kind: "secret" }], next: null }), null);
  assert.equal(readClientsPage({ clients: [{ ...portal, keys: -1 }], next: null }), null);
  assert.equal(readClientsPage({ clients: [{ ...portal, sector: "cloud" }], next: null })?.clients[0]?.sector, "cloud");
  assert.equal(readClientsPage({ clients: [{ ...portal, sector: 3 }], next: null }), null);
  const unlisted = { ...portal, redirect_uris: "https://app.example/cb" };
  assert.equal(readClientsPage({ clients: [unlisted], next: null }), null);
  assert.equal(readClientsPage({ clients: [], next: 3 }), null);
});

test("the cursor travels in the address and the view's own", () => {
  assert.equal(clientsPath(null), "api/clients");
  assert.equal(clientsPath("a b"), "api/clients?after=a+b");
  assert.deepEqual(route("#/clients?after=kiosk"), { kind: "clients", after: "kiosk" });
});

test("a list field holds one value per line or space, empty ones dropped", () => {
  assert.deepEqual(listOf(" https://a.example/cb \n\n https://b.example/cb"), [
    "https://a.example/cb",
    "https://b.example/cb",
  ]);
  assert.deepEqual(listOf("openid  orders:read"), ["openid", "orders:read"]);
  assert.deepEqual(listOf("  "), []);
});

const form = {
  id: "shop",
  confidential: false,
  algorithm: "EdDSA",
  jwk: "",
  redirects: "https://shop.example/cb",
  scopes: "openid orders:read",
  resources: "",
  grants: ["authorization_code", "refresh_token"],
  dpop: false,
  sector: "",
};

test("a public client is described with no keys and no algorithm", () => {
  assert.deepEqual(registrationOf(form), {
    body: {
      client_id: "shop",
      redirect_uris: ["https://shop.example/cb"],
      scope_ceiling: ["openid", "orders:read"],
      resources: [],
      auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      dpop_bound_access_tokens: false,
    },
  });
});

test("a confidential client carries its algorithm and its public key as an object", () => {
  const jwk = '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';
  const made = registrationOf({ ...form, confidential: true, jwk, redirects: "", grants: ["client_credentials"] });
  assert.deepEqual(made, {
    body: {
      client_id: "shop",
      redirect_uris: [],
      scope_ceiling: ["openid", "orders:read"],
      resources: [],
      auth_method: "private_key_jwt",
      assertion_alg: "EdDSA",
      jwks: [JSON.parse(jwk)],
      grant_types: ["client_credentials"],
      dpop_bound_access_tokens: false,
    },
  });
});

test("a sector, when given, travels with the registration", () => {
  const made = registrationOf({ ...form, sector: " tessaridb-cloud " });
  assert.equal("body" in made && made.body.sector, "tessaridb-cloud");
});

test("a form outside the rules names the field to fix", () => {
  const wrong = (changed) => {
    const made = registrationOf({ ...form, ...changed });
    return "wrong" in made ? made.wrong : null;
  };
  assert.equal(wrong({ id: "" }), "id");
  assert.equal(wrong({ id: "bad\u0007id" }), "id");
  assert.equal(wrong({ grants: [] }), "grants");
  assert.equal(wrong({ redirects: "" }), "redirects");
  assert.equal(wrong({ grants: ["client_credentials"], redirects: "" }), "grants");
  assert.equal(wrong({ confidential: true, jwk: "" }), "jwk");
  assert.equal(wrong({ confidential: true, jwk: "[1]" }), "jwk");
  assert.equal(wrong({ confidential: true, jwk: '{"kty":"OKP"}', algorithm: "HS256" }), "algorithm");
  assert.equal(wrong({ sector: "Cloud Site" }), "sector");
  assert.equal(wrong({ sector: "-cloud" }), "sector");
});

test("each refused registration says what to do next", () => {
  assert.match(clientRefusalText("client_taken"), /another id/);
  assert.match(clientRefusalText("client_reserved"), /console/);
  assert.notEqual(clientRefusalText("client_taken"), clientRefusalText("client_reserved"));
});

test("a removal is addressed by the client id, escaped, and its holders read from the one client", () => {
  assert.equal(clientPath("a b/c"), "api/clients/a%20b%2Fc");
  assert.equal(removalPath("a b/c"), "api/clients/a%20b%2Fc/remove");
  assert.equal(readHolders({ ...portal, holders: 3 }), 3);
  assert.equal(readHolders({ ...portal, holders: -1 }), null);
  assert.equal(readHolders({ ...portal, holders: "3" }), null);
  assert.equal(readHolders(portal), null);
});

test("a removal answer is read whole, and any part of another shape makes it unreadable", () => {
  const answer = { client_id: "portal", consents: 2, families: 1, access_tokens_end_by: 1800000300 };
  assert.deepEqual(readRemoved(answer), {
    clientId: "portal",
    consents: 2,
    families: 1,
    accessTokensEndBy: 1800000300,
  });
  assert.equal(readRemoved({ ...answer, consents: 1.5 }), null);
  assert.equal(readRemoved({ ...answer, client_id: "" }), null);
  assert.equal(readRemoved({ ...answer, families: undefined }), null);
});

test("a refused removal says what happened, not how to register", () => {
  assert.match(clientRemovalRefusalText("client_reserved"), /not removed/);
  assert.doesNotMatch(clientRemovalRefusalText("client_reserved"), /another id/);
});
