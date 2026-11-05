const KNOWN_DOMAINS = [
  "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
  "facebook.com", "instagram.com", "netflix.com", "linkedin.com",
  "dropbox.com", "github.com", "outlook.com", "office365.com", "gmail.com",
  "yahoo.com", "ebay.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
  "anz.co.nz", "asb.co.nz", "westpac.co.nz", "kiwibank.co.nz", "bnz.co.nz",
  "ird.govt.nz", "nzpost.co.nz", "spark.co.nz",
  // Added after real-data testing revealed these are the actual dominant
  // phishing targets today: crypto wallets/exchanges, gaming, telecoms.
  "roblox.com", "whatsapp.com", "coinbase.com", "metamask.io", "ledger.com",
  "trezor.io", "kucoin.com", "trustwallet.com", "xfinity.com", "comcast.com",
  "docusign.com", "santander.com", "bbva.com", "dhl.com", "spotify.com",
  "opensea.io", "exodus.com", "adobe.com",
];

const BRANDS = Array.from(new Set(KNOWN_DOMAINS.map(d => d.split(".")[0]).filter(b => b.length >= 4)));
const BRAND_ROOTS = KNOWN_DOMAINS.filter(d => d.split(".")[0].length >= 4);

const SUSPICIOUS_TLDS = [".xyz",".top",".tk",".club",".click",".work",".loan",".men",".gq",".cf",".ml",".info",".win",".bid"];
const SHORTENER_DOMAINS = ["bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","buff.ly","is.gd","tiny.cc","rebrand.ly","cutt.ly","rb.gy","shorturl.at","s.id","tr.im"];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({length: m+1}, () => new Array(n+1).fill(0));
  for (let i=0;i<=m;i++) dp[i][0]=i;
  for (let j=0;j<=n;j++) dp[0][j]=j;
  for (let i=1;i<=m;i++) for (let j=1;j<=n;j++) {
    const cost = a[i-1]===b[j-1]?0:1;
    dp[i][j]=Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost);
  }
  return dp[m][n];
}

function checkTyposquatting(domain) {
  if (KNOWN_DOMAINS.includes(domain)) return null;
  let closest = "", bestDistance = Infinity;
  for (const known of KNOWN_DOMAINS) {
    const d = levenshtein(domain, known);
    if (d < bestDistance) { bestDistance = d; closest = known; }
  }
  const wholeThreshold = closest.length <= 8 ? 1 : 2;
  if (bestDistance > 0 && bestDistance <= wholeThreshold) return { rule: "typosquat-whole", closest };

  const tokens = domain.split(/[.-]/).filter(t => t.length >= 4);
  for (const token of tokens) {
    let tClosest = "", tBest = Infinity;
    for (const brand of BRANDS) {
      const d = levenshtein(token, brand);
      if (d < tBest) { tBest = d; tClosest = brand; }
    }
    const tokenThreshold = tClosest.length <= 8 ? 1 : 2;
    if (tBest > 0 && tBest <= tokenThreshold) return { rule: "typosquat-token", token, tClosest };
  }
  return null;
}

// NEW: catches a known brand name used verbatim inside a domain that isn't
// actually that brand's domain (e.g. "coinbaseverify.vercel.app",
// "wellsfargogethelp.com", "instagram-security-team.vercel.app"). This is
// distinct from typosquatting (which looks for near-misses) — here the
// brand name is exact, just glued onto unrelated infrastructure.
function checkBrandImpersonation(domain) {
  if (KNOWN_DOMAINS.includes(domain)) return null;
  for (let i = 0; i < BRAND_ROOTS.length; i++) {
    const root = BRAND_ROOTS[i];
    const brand = root.split(".")[0];
    if (domain === root || domain.endsWith("." + root)) return null; // legitimate subdomain
    if (domain.includes(brand)) return { rule: "brand-impersonation", brand, root };
  }
  return null;
}

function checkTld(domain) {
  for (const tld of SUSPICIOUS_TLDS) if (domain.endsWith(tld)) return { rule: "tld" };
  return null;
}
function checkShortener(domain) {
  return SHORTENER_DOMAINS.includes(domain) ? { rule: "shortener" } : null;
}

function evaluate(domain) {
  return checkTyposquatting(domain) || checkBrandImpersonation(domain) || checkTld(domain) || checkShortener(domain);
}

const PHISHING_DOMAINS = [
  "ledgerlive0.godaddysites.com","kucoinievlosginie.godaddysites.com","santander.firstjob.me",
  "bbvasecurities.com","en-ledgre.pages.dev","panel-deploy-60bef09b.us-iad-10.linodeobjects.com",
  "roblox.com.do","wildlands.acltci.com","wellsfargogethelp.com","public-trexor.framer.website",
  "roblox.com.ml","roblox.com.am","facebook-trial.vercel.app","cn.ember-whatsapp.com",
  "xfinity101.duckdns.org","kauadosantos.github.io","ptai.in","whatsapp7g.blogspot.com",
  "xfinityteamsservice.weebly.com","coinbaseverify.vercel.app",
  "ehay.item.com.login.se.eddiesresidence.co.tz","swyftxfinancial.com","microsoft.github.io",
  "instagram-security-team.vercel.app","dhl-express-dev.firebaseapp.com",
  "start-ledgerlive-com-web.typedream.app","webpage-trezor-suite.typedream.app",
  "feq-trezor-suite-app.typedream.app","ledger-wallet-start-cloud.typedream.app",
  "support-ledgerlive-eng.typedream.app","xfinityteamslogin.weebly.com","microsoft-0r.github.io",
  "republicanlibertycaucus.org","auth.properties","instagram-new-version.vercel.app","roblox.com.ee",
  "eu-assets.contentstack.com","carsscanned.ebaymclaren-austin.eventshouse.app","xfinity003.weebly.com",
  "comcastwebmailuser.weebly.com","roblox.com.bo","cn-feed-whatsapp.com.cn",
  "instagram-login-support.vercel.app","androidguias.com","docusign-server.github.io",
  "synel99.github.io","lobologisticgroup.com.mx","trezorwollet.webador.com","netflix.yogufile.shop",
  "kucoinloginaa.gitbook.io","taslimaenterprise.com","marycar.com.br",
];

const LEGIT_DOMAINS = [
  ...KNOWN_DOMAINS,
  "wikipedia.org","reddit.com","stackoverflow.com","twitter.com","trademe.co.nz",
  "stuff.co.nz","nzherald.co.nz","mega.nz","canva.com","discord.com",
  "twitch.tv","steamcommunity.com",
];

console.log("=== PHISHING SET (real, live data) — after fix ===");
let tp = 0; const missed = [];
for (const d of PHISHING_DOMAINS) { const r = evaluate(d); if (r) tp++; else missed.push(d); }
console.log(`Flagged: ${tp} / ${PHISHING_DOMAINS.length} (${(100*tp/PHISHING_DOMAINS.length).toFixed(1)}%)`);
console.log(`Still missed (${missed.length}):`, missed);

console.log("\n=== LEGITIMATE SET — after fix ===");
let fp = 0; const flagged = [];
for (const d of LEGIT_DOMAINS) { const r = evaluate(d); if (r) { fp++; flagged.push({d, r}); } }
console.log(`False positives: ${fp} / ${LEGIT_DOMAINS.length} (${(100*fp/LEGIT_DOMAINS.length).toFixed(1)}%)`);
flagged.forEach(f => console.log("  -", f.d, JSON.stringify(f.r)));
