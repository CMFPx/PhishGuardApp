// Compares three versions of the domain rules on every dataset in ./data.
//   v6  frozen copy of the rules deployed on 24 Sep (the baseline)
//   v7  interim version (kept so the table in README.md can be reproduced)
//   v8  the live code, imported from the Edge Function's rules.ts
// Run: node domain-rules-test-v2.mjs  (Node 22.18 or newer)
//
// Only domain rules are covered (typosquatting, brand impersonation, TLD,
// shortener, free-host). Urgency/greeting rules need message text and the
// domain-age rule needs a live network call, so neither is tested here.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeDomain } from "../supabase/functions/analyze/rules.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const load = (f) => JSON.parse(fs.readFileSync(path.join(here, "data", f), "utf8"));

// ---------- shared data ----------
const KNOWN_DOMAINS = [
  "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
  "facebook.com", "instagram.com", "netflix.com", "linkedin.com",
  "dropbox.com", "github.com", "outlook.com", "office365.com", "gmail.com",
  "yahoo.com", "ebay.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
  "anz.co.nz", "asb.co.nz", "westpac.co.nz", "kiwibank.co.nz", "bnz.co.nz",
  "ird.govt.nz", "nzpost.co.nz", "spark.co.nz",
  "roblox.com", "whatsapp.com", "coinbase.com", "metamask.io", "ledger.com",
  "trezor.io", "kucoin.com", "trustwallet.com", "xfinity.com", "comcast.com",
  "docusign.com", "santander.com", "bbva.com", "dhl.com", "spotify.com",
  "opensea.io", "exodus.com", "adobe.com",
];
const BRANDS = [...new Set(KNOWN_DOMAINS.map((d) => d.split(".")[0]).filter((b) => b.length >= 4))];
const BRAND_ROOTS = KNOWN_DOMAINS.filter((d) => d.split(".")[0].length >= 4);
const SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".club", ".click", ".work", ".loan", ".men", ".gq", ".cf", ".ml", ".info", ".win", ".bid"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly", "is.gd", "tiny.cc", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "s.id", "tr.im"];
const FREE_HOSTS = ["godaddysites.com", "weebly.com", "github.io", "vercel.app", "typedream.app", "framer.website", "webador.com", "gitbook.io", "duckdns.org", "firebaseapp.com", "blogspot.com", "pages.dev", "contentstack.com", "linodeobjects.com", "eventshouse.app", "netlify.app", "square.site", "webflow.io", "wasmer.app"];

// v7 only: legitimate domains that contain or resemble a monitored brand.
const SAFE_ROOTS = [
  "amazonaws.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
  "githubusercontent.com", "microsoftonline.com", "office.com", "live.com",
  "onedrive.com", "paypalobjects.com", "paypal.me", "adobe.io", "facebook.net",
  "fbcdn.net", "gitlab.com",
];
// v7 only: regional versions of a monitored brand, e.g. amazon.co.nz.
const REGIONAL = ["co.nz", "co.uk", "com.au", "ca", "de", "fr", "co.jp", "in", "com.br", "com.mx"];
// v7 only: short brands, matched as a whole hyphen/dot-separated token only.
const SHORT_BRANDS = [
  { brand: "dhl", root: "dhl.com" }, { brand: "anz", root: "anz.co.nz" },
  { brand: "asb", root: "asb.co.nz" }, { brand: "bnz", root: "bnz.co.nz" },
  { brand: "ird", root: "ird.govt.nz" },
];

// ---------- distance functions ----------
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}
// Optimal string alignment: like Levenshtein but a swap of two neighbouring
// letters ("ledgre" for "ledger") costs 1 instead of 2.
function osa(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
    }
  return dp[a.length][b.length];
}

// Maps look-alike characters to the letter they imitate before comparing,
// so "paypa1" and "arnazon" are read as "paypal" and "amazon".
const normalise = (s) => s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s");

const isUnder = (d, root) => d === root || d.endsWith("." + root);

// ---------- v6: what is deployed now ----------
function v6(domain) {
  if (KNOWN_DOMAINS.includes(domain)) return null;
  let closest = "", best = Infinity;
  for (const k of KNOWN_DOMAINS) { const d = levenshtein(domain, k); if (d < best) { best = d; closest = k; } }
  if (best > 0 && best <= (closest.length <= 8 ? 1 : 2)) return "typosquat-whole";
  for (const t of domain.split(/[.-]/).filter((t) => t.length >= 4)) {
    let tb = Infinity, tc = "";
    for (const b of BRANDS) { const d = levenshtein(t, b); if (d < tb) { tb = d; tc = b; } }
    if (tb > 0 && tb <= (tc.length <= 8 ? 1 : 2)) return "typosquat-token";
  }
  for (const root of BRAND_ROOTS) {
    if (isUnder(domain, root)) continue;
    if (domain.includes(root.split(".")[0])) return "brand-impersonation";
  }
  if (SUSPICIOUS_TLDS.some((t) => domain.endsWith(t))) return "tld";
  if (SHORTENERS.includes(domain)) return "shortener";
  return null;
}

// ---------- v7: candidate ----------
// Returns the part of the hostname the registrant controls. On a free host
// (pytorch.github.io) the platform name is not part of the claim being made.
function ownedPart(domain) {
  const h = FREE_HOSTS.find((h) => isUnder(domain, h));
  return h ? domain.slice(0, domain.length - h.length).replace(/\.$/, "") : domain;
}

function v7(domain) {
  if (KNOWN_DOMAINS.some((k) => isUnder(domain, k))) return null; // the real brand or a subdomain of it
  if (SAFE_ROOTS.some((r) => isUnder(domain, r))) return null;
  for (const root of BRAND_ROOTS) {
    const brand = root.split(".")[0];
    if (REGIONAL.some((r) => isUnder(domain, `${brand}.${r}`))) return null;
  }
  const owned = ownedPart(domain);
  const norm = normalise(owned);

  // whole-domain look-alike: one edit after normalising look-alike characters
  let closest = "", best = Infinity;
  for (const k of KNOWN_DOMAINS) { const d = osa(normalise(domain), k); if (d < best) { best = d; closest = k; } }
  if (best <= 1) return "typosquat-whole";

  for (const t of norm.split(/[.-]/).filter((t) => t.length >= 4)) {
    let tb = Infinity;
    for (const b of BRANDS) { const d = osa(t, b); if (d < tb) tb = d; }
    if (tb === 1) return "typosquat-token";
  }
  for (const root of BRAND_ROOTS) {
    if (norm.includes(root.split(".")[0])) return "brand-impersonation";
  }
  const tokens = owned.split(/[.-]/);
  for (const { brand } of SHORT_BRANDS) {
    if (tokens.includes(brand)) return "short-brand-token";
  }
  if (SUSPICIOUS_TLDS.some((t) => domain.endsWith(t))) return "tld";
  if (SHORTENERS.includes(domain)) return "shortener";
  return null;
}

const onFreeHost = (d) => FREE_HOSTS.some((h) => isUnder(d, h));

// ---------- v8: the real thing ----------
const v8findings = (d) => analyzeDomain(d);
const v8 = (d) => v8findings(d).find((f) => f.category !== "free-host")?.rule ?? null;
const v8free = (d) => v8findings(d).some((f) => f.category === "free-host");

// ---------- reporting ----------
const pct = (n, d) => `${n}/${d} (${((100 * n) / d).toFixed(1)}%)`;
const legit = load("legit.json");
const datasets = fs.readdirSync(path.join(here, "data")).filter((f) => f.startsWith("sample-")).sort();

console.log("=== LEGITIMATE DOMAINS: how many get flagged ===");
const groups = [
  ["primary", legit.primary], ["related", legit.related],
  ["free-hosted", legit.free_hosted], ["unrelated, brand inside", legit.unrelated_containing_brand],
];
for (const [label, list] of groups) {
  const f6 = list.filter((d) => v6(d)), f7 = list.filter((d) => v7(d)), f8 = list.filter((d) => v8(d));
  console.log(`${label.padEnd(24)} v6 ${pct(f6.length, list.length).padEnd(14)} v7 ${pct(f7.length, list.length).padEnd(14)} v8 ${pct(f8.length, list.length)}`);
  if (f8.length) console.log("   v8 flagged:", f8.map((d) => `${d} [${v8(d)}]`).join(", "));
}
const freeLegit = legit.free_hosted.filter(v8free).length;
console.log(`free-host weak signal on legit free-hosted sites: ${pct(freeLegit, legit.free_hosted.length)}`);

for (const f of datasets) {
  const ds = load(f);
  const p = ds.phishing;
  const h6 = p.filter(v6), h7 = p.filter(v7), h8 = p.filter(v8);
  const weakOnly = p.filter((d) => !v8(d) && v8free(d));
  const none = p.filter((d) => !v8(d) && !v8free(d));
  console.log(`\n=== ${ds.name} (${p.length} domains) ===`);
  console.log(`v6  ${pct(h6.length, p.length)}`);
  console.log(`v7  ${pct(h7.length, p.length)}`);
  console.log(`v8  ${pct(h8.length, p.length)}`);
  console.log(`v8 + free-host weak signal  ${pct(h8.length + weakOnly.length, p.length)}`);
  const by = {};
  for (const d of h8) by[v8(d)] = (by[v8(d)] || 0) + 1;
  console.log("v8 hits by rule:", JSON.stringify(by));
  console.log("v8 misses with no signal:", none.join(", "));
  console.log("v8 misses, free host only:", weakOnly.join(", "));
}
