// Detection rules for PhishGuard. Everything in this file is pure logic with no
// Deno or network calls, so the same code runs in the Edge Function (index.ts)
// and in the evaluation scripts under /evaluation. What gets tested is what
// gets deployed.

export type Level = "high" | "medium" | "low" | "neutral";
export type Indicator = { level: Level; title: string; desc: string };
export type DomainFinding = Indicator & { rule: string; category: "brand" | "tld" | "shortener" | "free-host" };

// ---------- data ----------

// Brands that phishing pretends to be. The first group was chosen up front
// (big tech, banks, NZ services). The second group was added after testing
// against live phishing feeds showed what attackers really impersonate:
// crypto wallets and exchanges, gaming, telecoms, parcel and file-sharing
// services.
export const KNOWN_DOMAINS = [
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
  "zoom.us", "usps.com", "seur.com", "wetransfer.com", "binance.com", "onedrive.com",
];

// Legitimate domains that contain or resemble a monitored brand. Without this
// list the brand rules flag things like amazonaws.com and gitlab.com.
export const SAFE_ROOTS = [
  "amazonaws.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
  "githubusercontent.com", "microsoftonline.com", "office.com", "live.com",
  "paypalobjects.com", "paypal.me", "adobe.io", "facebook.net", "fbcdn.net",
  "gitlab.com",
];

// Country versions of a monitored brand, e.g. amazon.co.nz or apple.com.au.
// roblox.com.ml is not on this list, which is the point: that pattern is a
// common phishing trick.
export const REGIONAL = ["co.nz", "co.uk", "com.au", "ca", "de", "fr", "co.jp", "in", "com.br", "com.mx"];

// Brands too short for substring matching (it would hit unrelated words), so
// they only count when they appear as a whole hyphen or dot separated token.
export const SHORT_BRANDS = ["dhl", "anz", "asb", "bnz", "ird"];

export const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".tk", ".club", ".click", ".work", ".loan", ".men",
  ".gq", ".cf", ".ml", ".info", ".win", ".bid",
];

export const SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly", "is.gd",
  "tiny.cc", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "s.id", "tr.im",
  "goo.su", "lnk.ink", "t.ly", "v.gd",
];

// Hosting platforms where anyone can publish a page under a subdomain.
export const FREE_HOSTS = [
  "godaddysites.com", "weebly.com", "github.io", "vercel.app", "typedream.app",
  "framer.website", "webador.com", "gitbook.io", "duckdns.org", "firebaseapp.com",
  "blogspot.com", "pages.dev", "contentstack.com", "linodeobjects.com",
  "eventshouse.app", "netlify.app", "square.site", "webflow.io", "wasmer.app",
];

const BRANDS = [...new Set(KNOWN_DOMAINS.map((d) => d.split(".")[0]).filter((b) => b.length >= 4))];

const URGENCY_PHRASES = [
  "act now", "verify immediately", "account.*suspend", "act fast",
  "claim now", "claim your", "limited time", "expires? (soon|today|in)",
  "urgent action", "immediate action", "before it'?s too late",
  "confirm your details", "unauthorized (access|activity)", "unusual activity",
  "winner", "you'?ve won", "congratulations", "free (gift|reward|prize)",
  "click here now", "final notice", "failure to (comply|respond|act)",
];
const URGENCY_REGEX = new RegExp(URGENCY_PHRASES.join("|"), "i");

// ---------- string helpers ----------

// Edit distance where swapping two neighbouring letters counts as one edit,
// so "ledgre" is one step from "ledger".
export function osa(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, (_, i) => {
    const row = new Array(b.length + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[a.length][b.length];
}

// Reads look-alike characters as the letter they imitate, so "paypa1" is
// compared as "paypal" and "arnazon" as "amazon".
export function normalise(s: string): string {
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s");
}

const isUnder = (domain: string, root: string) => domain === root || domain.endsWith("." + root);

export function extractDomains(text: string): string[] {
  const found = new Set<string>();
  const re = /(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) found.add(m[1].toLowerCase());
  return [...found];
}

// The part of a hostname the registrant controls. On a free host such as
// pytorch.github.io the platform name says nothing about who made the page.
export function ownedPart(domain: string): string {
  const host = FREE_HOSTS.find((h) => isUnder(domain, h));
  return host ? domain.slice(0, domain.length - host.length).replace(/\.$/, "") : domain;
}

// True for a monitored brand's own domain, its subdomains, its country
// versions, and known safe look-alikes.
export function isExempt(domain: string): boolean {
  if (KNOWN_DOMAINS.some((k) => isUnder(domain, k))) return true;
  if (SAFE_ROOTS.some((r) => isUnder(domain, r))) return true;
  for (const k of KNOWN_DOMAINS) {
    const brand = k.split(".")[0];
    if (REGIONAL.some((r) => isUnder(domain, `${brand}.${r}`))) return true;
  }
  return false;
}

// ---------- domain rules ----------

function brandFinding(domain: string): DomainFinding | null {
  const owned = ownedPart(domain);
  const norm = normalise(owned);
  const tokens = norm.split(/[.-]/).filter(Boolean);
  const compact = tokens.join("");

  // 1. The whole domain is one edit away from a known domain.
  let closest = "";
  let best = Infinity;
  const normDomain = normalise(domain);
  for (const k of KNOWN_DOMAINS) {
    const d = osa(normDomain, k);
    if (d < best) { best = d; closest = k; }
  }
  if (best <= 1) {
    return {
      rule: "typosquat-whole", category: "brand", level: "high", title: "Suspicious domain",
      desc: `"${domain}" is almost identical to "${closest}" and is probably imitating it.`,
    };
  }

  // 2. A brand name sits in the domain as its own word, e.g. coinbase-verify.vercel.app.
  for (const b of BRANDS) {
    if (tokens.includes(b)) {
      return {
        rule: "brand-token", category: "brand", level: "high", title: "Suspicious domain",
        desc: `"${domain}" uses the brand name "${b}" but is not an official ${b} domain.`,
      };
    }
  }

  // 3. A word in the domain is one edit away from a brand, e.g. paypa1 or ledgre.
  for (const t of tokens.filter((t) => t.length >= 4)) {
    for (const b of BRANDS) {
      if (osa(t, b) === 1) {
        return {
          rule: "typosquat-token", category: "brand", level: "high", title: "Suspicious domain",
          desc: `"${domain}" contains "${t}", a near-miss spelling of the brand "${b}".`,
        };
      }
    }
  }

  // 4. A brand name is buried inside a longer word, e.g. coinbaseverify.com.
  // This also matches innocent words (applebees, zoominfo), so it ranks lower.
  for (const b of BRANDS) {
    if (compact.includes(b)) {
      return {
        rule: "brand-embedded", category: "brand", level: "medium", title: "Possible brand imitation",
        desc: `"${domain}" contains the brand name "${b}" inside a longer name and is not an official ${b} domain.`,
      };
    }
  }

  // 5. Short brands, as whole tokens only.
  const rawTokens = owned.split(/[.-]/);
  for (const b of SHORT_BRANDS) {
    if (rawTokens.includes(b)) {
      return {
        rule: "short-brand-token", category: "brand", level: "high", title: "Suspicious domain",
        desc: `"${domain}" uses the brand name "${b}" but is not an official ${b} domain.`,
      };
    }
  }
  return null;
}

export function analyzeDomain(domain: string): DomainFinding[] {
  const out: DomainFinding[] = [];
  if (isExempt(domain)) return out;

  const brand = brandFinding(domain);
  if (brand) out.push(brand);

  const tld = SUSPICIOUS_TLDS.find((t) => domain.endsWith(t));
  if (tld) {
    out.push({
      rule: "tld", category: "tld", level: "medium", title: "Suspicious TLD",
      desc: `"${domain}" ends in "${tld}", which is used far more often for phishing and spam than most endings.`,
    });
  }

  if (SHORTENERS.includes(domain)) {
    out.push({
      rule: "shortener", category: "shortener", level: "medium", title: "URL shortener",
      desc: `"${domain}" is a link shortener, which can hide where the link really goes.`,
    });
  }

  if (FREE_HOSTS.some((h) => isUnder(domain, h))) {
    out.push({
      rule: "free-host", category: "free-host", level: "low", title: "Free hosting platform",
      desc: `"${domain}" is hosted on a platform where anyone can publish a page for free. Many legitimate sites do this too, so this only adds a little weight.`,
    });
  }
  return out;
}

// ---------- link structure rules ----------
// These look at how a link is built, not which brand it names, so they work
// even when the brand list has no entry for the site being imitated.

export type ParsedLink = { host: string; user: string; path: string; hasScheme: boolean };

// Words that turn a brand name in a link path from "a page about Adobe" into
// "a fake Adobe sign-in page".
const SENSITIVE_PATH_WORDS = [
  "login", "signin", "auth", "secure", "verify", "account", "otp", "password",
  "mailbox", "upgrade", "installer", "update", "wallet", "billing", "confirm",
];

export function extractLinks(text: string): ParsedLink[] {
  const out: ParsedLink[] = [];
  const withScheme = /https?:\/\/[^\s<>"')\]]+/gi;
  let m: RegExpExecArray | null;
  while ((m = withScheme.exec(text)) !== null) {
    try {
      const u = new URL(m[0]);
      out.push({ host: u.hostname.toLowerCase(), user: u.username, path: u.pathname + u.search, hasScheme: true });
    } catch { /* not a valid URL, skip it */ }
  }
  // Links pasted without http(s)://, such as example.com/login. Path rules only.
  const bare = /(?<![\w@.\/-])((?:[a-z0-9-]+\.)+[a-z]{2,})(\/[^\s<>"')\]]*)/gi;
  while ((m = bare.exec(text)) !== null) {
    out.push({ host: m[1].toLowerCase(), user: "", path: m[2], hasScheme: false });
  }
  return out;
}

function isPublicIp(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return false;
  const [a, b] = parts.map(Number);
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  return true;
}

function brandInPath(path: string): string | null {
  let decoded = path;
  try { decoded = decodeURIComponent(path); } catch { /* keep the raw path */ }
  const lower = decoded.toLowerCase();

  // A full brand domain written into the path, e.g. /accounts.google.com/
  for (const k of KNOWN_DOMAINS) if (lower.includes(k)) return k;

  // A brand word together with a sign-in style word, e.g. /port/paypal/auth/login.php
  // Hyphenated slugs longer than three words are article or question titles
  // (how-to-login-with-google-oauth), so they are skipped. Short ones such as
  // paypal-login still count.
  const tokens: string[] = [];
  for (const seg of lower.split(/[^a-z0-9-]+/)) {
    const parts = seg.split("-").filter(Boolean);
    if (parts.length <= 3) tokens.push(...parts.map((t) => t.replace(/\d+$/, "")));
  }
  const brand = BRANDS.find((b) => tokens.includes(b));
  if (brand && SENSITIVE_PATH_WORDS.some((w) => tokens.includes(w))) return brand;
  return null;
}

export function checkLinkStructure(text: string): Indicator[] {
  const found: Indicator[] = [];
  const add = (i: Indicator) => { if (!found.some((f) => f.title === i.title)) found.push(i); };

  for (const link of extractLinks(text)) {
    if (link.hasScheme && isPublicIp(link.host)) {
      add({
        level: "high", title: "Link uses an IP address",
        desc: `"${link.host}" is a raw IP address instead of a website name. Real companies almost never send links like this.`,
      });
    }
    if (link.hasScheme && link.user) {
      add({
        level: "high", title: "Link hides its real destination",
        desc: `The link contains an "@" sign. Browsers ignore everything before it, so the real site is "${link.host}", not what the start of the link suggests.`,
      });
    }
    if (link.host.split(".").some((l) => l.startsWith("xn--"))) {
      add({
        level: "medium", title: "Look-alike characters in domain",
        desc: `"${link.host}" uses special characters that can imitate normal letters (an "xn--" domain).`,
      });
    }
    if (link.host.split(".").length >= 5 && !isExempt(link.host)) {
      add({
        level: "low", title: "Very long subdomain chain",
        desc: `"${link.host}" has many parts in front of the real domain, a common way to bury the real site name.`,
      });
    }
    if (!isExempt(link.host)) {
      const brand = brandInPath(link.path);
      if (brand) {
        add({
          level: "medium", title: "Brand name in link path",
          desc: `The link goes to "${link.host}" but its address contains "${brand}", which makes it look like it belongs to that brand.`,
        });
      }
    }
  }
  return found;
}

// ---------- message rules ----------

const SENSITIVE_REQUEST = new RegExp(
  "\\b(enter|confirm|provide|verify|send|update|reply with|submit)\\b\\W+(?:\\w+\\W+){0,3}" +
  "(password|passcode|pin|card number|cvv|credit card|bank details|login details|security code)",
  "i",
);

export function checkSensitiveRequest(text: string): Indicator | null {
  const m = text.match(SENSITIVE_REQUEST);
  if (!m) return null;
  return {
    level: "medium", title: "Asks for sensitive details",
    desc: `The message asks you to hand over private information ("${m[0].trim()}"). Legitimate companies do not ask for this by email or message.`,
  };
}

export function checkUrgency(text: string): Indicator | null {
  const m = text.match(URGENCY_REGEX);
  if (!m) return null;
  return { level: "high", title: "Urgency language", desc: `Contains pressure wording common in phishing ("${m[0]}").` };
}

export function checkGenericGreeting(text: string): Indicator | null {
  if (/dear customer|dear user/i.test(text)) {
    return { level: "medium", title: "Generic greeting", desc: "The message does not use your name." };
  }
  return null;
}

// Everything except the domain age lookup, which needs the network.
export function analyzeStatic(text: string): Indicator[] {
  const indicators: Indicator[] = [];
  const urgency = checkUrgency(text);
  if (urgency) indicators.push(urgency);
  const greeting = checkGenericGreeting(text);
  if (greeting) indicators.push(greeting);
  const sensitive = checkSensitiveRequest(text);
  if (sensitive) indicators.push(sensitive);

  const seen = new Set<string>();
  for (const domain of extractDomains(text)) {
    for (const f of analyzeDomain(domain)) {
      if (seen.has(f.category)) continue;
      seen.add(f.category);
      indicators.push({ level: f.level, title: f.title, desc: f.desc });
    }
  }
  indicators.push(...checkLinkStructure(text));
  return indicators;
}

const POINTS: Record<Level, number> = { high: 35, medium: 20, low: 8, neutral: 0 };

export function scoreIndicators(indicators: Indicator[]): number {
  return Math.min(100, 10 + indicators.reduce((sum, i) => sum + POINTS[i.level], 0));
}

// The same thresholds the results panel uses to colour the gauge.
export function riskLevel(score: number): "high" | "medium" | "low" {
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}
