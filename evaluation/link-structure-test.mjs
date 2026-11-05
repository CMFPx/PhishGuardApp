// Checks the link-structure rules (IP address, @ in link, punycode, long
// subdomain chain, brand name in path) on:
//   1. the 116 real phishing URLs from the 16 Oct OpenPhish pull (data/raw-2026-10-16.txt)
//   2. 30 hand-written legitimate links with paths (data/legit-urls.json)
// Run: node link-structure-test.mjs  (Node 22.18 or newer)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkLinkStructure, analyzeDomain, extractDomains } from "../supabase/functions/analyze/rules.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const phishing = fs.readFileSync(path.join(here, "data", "raw-2026-10-16.txt"), "utf8").split(/\r?\n/).filter(Boolean);
const legit = JSON.parse(fs.readFileSync(path.join(here, "data", "legit-urls.json"), "utf8")).urls;

const domainRulesFire = (u) => extractDomains(u).some((d) => analyzeDomain(d).some((f) => f.category !== "free-host"));
const structural = (u) => checkLinkStructure(u).map((i) => i.title);

console.log("=== PHISHING URLs (116) ===");
const byTitle = {};
let anyStructural = 0, newOnly = 0;
const newOnlyList = [];
for (const u of phishing) {
  const t = structural(u);
  if (t.length) anyStructural++;
  for (const x of t) byTitle[x] = (byTitle[x] || 0) + 1;
  if (t.length && !domainRulesFire(u)) { newOnly++; newOnlyList.push(u); }
}
console.log("structural rule fired on:", anyStructural, "/", phishing.length);
console.log("by rule:", JSON.stringify(byTitle));
console.log("fired AND missed by the domain rules (real gain):", newOnly);
for (const u of newOnlyList) console.log("   ", u);

const domainOnly = phishing.filter(domainRulesFire).length;
console.log(`domain rules alone: ${domainOnly}/${phishing.length}; with structural rules: ${phishing.filter((u) => domainRulesFire(u) || structural(u).length).length}/${phishing.length}`);

console.log("\n=== LEGITIMATE links with paths (30, hand-written) ===");
let fp = 0;
for (const u of legit) {
  const t = structural(u);
  if (t.length) { fp++; console.log("  FLAGGED", u, "->", t.join(", ")); }
}
console.log(`structural rules flagged ${fp}/${legit.length}`);
