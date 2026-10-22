// Renders the pages' source into the committed assets under ../assets/.
//
// Building or running the server never comes through here: the output is committed and embedded by include_str!,
// so `cargo build`, `docker build` and a release need no Node. The build is deterministic, so running it twice
// changes no byte, which is what `verify.sh` checks. EVERY file under ../assets/ is written by this script.

import { build } from "esbuild";
import { copyFile, readFile } from "node:fs/promises";

const ASSETS = new URL("../assets/", import.meta.url);
const STATIC = new URL("./static/", import.meta.url);

/** Nothing a page loads may come from off this server: the pages work on a network with no route out. */
function local(what, text) {
  if (/\b(src|href)\s*=\s*["']?(https?:)?\/\//i.test(text) || /url\(\s*["']?(https?:)?\/\//i.test(text)) {
    throw new Error(`${what} reaches for something off this server`);
  }
}

for (const page of ["login", "consent"]) {
  await build({
    entryPoints: [new URL(`./src/${page}.ts`, import.meta.url).pathname],
    outfile: new URL(`${page}.js`, ASSETS).pathname,
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    charset: "utf8",
    legalComments: "inline",
    logLevel: "warning",
  });
  const script = await readFile(new URL(`${page}.js`, ASSETS), "utf8");
  local(`${page}.js`, script);
  // Does it PARSE: `Function` compiles the source without running it, so a script that would be a SyntaxError in
  // the browser fails the build instead.
  try {
    new Function(script);
  } catch (failure) {
    throw new Error(`${page}.js does not parse: ${failure.message}`);
  }
  console.log(`${`${page}.js`.padEnd(12)} ${script.length} bytes, parses`);
}

for (const name of ["login.html", "consent.html", "pages.css"]) {
  const text = await readFile(new URL(name, STATIC), "utf8");
  local(name, text);
  await copyFile(new URL(name, STATIC), new URL(name, ASSETS));
  console.log(`${name.padEnd(12)} copied`);
}

// The product mark has one home, the repository's logo directory; the pages serve that file, never a copy.
const MARK = new URL("../../../assets/logo/tessaridb-oauth-mark.svg", import.meta.url);
local("the product mark", await readFile(MARK, "utf8"));
await copyFile(MARK, new URL("mark.svg", ASSETS));
console.log("mark.svg     copied from assets/logo/tessaridb-oauth-mark.svg");
