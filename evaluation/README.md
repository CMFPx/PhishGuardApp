# Evaluation

`domain-rules-test.mjs` is a standalone Node script that replicates the
domain-based detection rules from `supabase/functions/analyze/index.ts`
(typosquatting, brand impersonation, suspicious TLD, URL shortener) so they
can be tested in bulk against real data without hitting the live Edge
Function or Supabase.

Run it with: `node evaluation/domain-rules-test.mjs`

## Methodology

Phishing sample domains were pulled from a live public feed
(phishunt.io, which cross-references OpenPhish) on 24 September 2026 —
52 currently-active phishing URLs, hostnames extracted. Legitimate sample
domains combine the app's own `KNOWN_DOMAINS` list plus other well-known
sites not in that list (including some of the exact brands being
impersonated in the phishing set, e.g. `roblox.com`, `whatsapp.com`,
`coinbase.com`, to fairly test that the real domain is never flagged).

This tests only the domain-based rules (not urgency language/generic
greeting, which need full message text, or domain age, which needs a live
network call not available in this harness).

## Results

| Run | True positive rate | False positive rate |
|---|---|---|
| Baseline (original `KNOWN_DOMAINS` list, near-miss typosquat check only) | 3.8% (2/52) | 0% (0/49) |
| After fix (expanded `KNOWN_DOMAINS`, added brand-impersonation check) | 75.0% (39/52) | 0% (0/57) |

**What the baseline run revealed:** the original `KNOWN_DOMAINS` list was
built around an assumption (major US tech/banks + NZ banks) rather than
evidence. Real, current phishing overwhelmingly targets crypto
wallets/exchanges (Ledger, Trezor, Coinbase, MetaMask, KuCoin,
TrustWallet), gaming (Roblox), telecoms (Xfinity/Comcast), and
international banks (Santander, BBVA) — none of which were covered.
Separately, the typosquat check only looked for *near-misses* of a brand
name (edit distance 1–2), but the dominant real pattern is an *exact*
brand name glued onto unrelated free-hosting infrastructure (e.g.
`wellsfargogethelp.com`, `coinbaseverify.vercel.app`) — a different
pattern requiring its own check.

**Remaining gap (13/52, 25%):** phishing sites using generic
infrastructure with no brand name anywhere in the domain (e.g.
`wildlands.acltci.com`, `androidguias.com`). These are not detectable by
any domain-name-based rule — catching them would require analysing page
content, which is out of scope for this project. Worth stating plainly in
the report as a known limitation rather than something to chase further.

Full results, including which specific rule caught each phishing domain,
are also logged in the `evaluation_results` table in Supabase.

## Round 2 (16 Oct 2026): testing on unseen data and a harder legitimate set

Run with `node domain-rules-test-v2.mjs` (Node 22.18 or newer). It loads every
`data/sample-*.json` plus `data/legit.json` and compares three versions of the
domain rules: v6 (deployed on 24 Sep), v7 (interim) and v8 (the live code in
`supabase/functions/analyze/rules.ts`, deployed as function version 9).
`rules-unit-test.mjs` holds 9 regression tests built from the manual test
sentences used earlier in the project.

| Dataset | v6 | v7 | v8 |
|---|---|---|---|
| 24 Sep OpenPhish (52) | 75.0% | 75.0% | 75.0% |
| 16 Oct OpenPhish (116) | 79.3% | 77.6% | 89.7% (tuned on this set) |
| 16 Oct PhishTank (23) | 43.5% | 43.5% | 43.5% (held out) |

Legitimate domains flagged (v6 / v8):

| Group | v6 | v8 |
|---|---|---|
| Primary brand domains (44) | 0 | 0 |
| Related, e.g. regional and subsidiary sites (27) | 16 | 0 |
| Free-hosted legitimate sites (4) | 4 | 0 |
| Unrelated domains with a brand word inside (3) | not measured | 3 |

What this shows:

- The 75% from September roughly holds on a new sample (v6 scored 79.3%), but
  part of v6's score came from flagging every github.io site, which also
  flagged legitimate ones.
- The earlier "0% false positives" only covered primary brand domains. On the
  harder "related" group v6 flagged 16 of 27. The related group was picked to
  be difficult, so this is a worst case and not a real-world rate.
- v8's 89.7% was tuned on the same sample it is scored on. The 43.5% on the
  PhishTank set is the honest held-out number, with only 23 domains behind it.
- Misses are mostly brands missing from the list (allegro, itau and others)
  and sites with no brand in the hostname. The brand list is the ceiling.
- Brand-embedded matches flag innocent words. All 3 unrelated domains with a
  brand word inside were flagged, at medium severity ("Possible brand
  imitation").
- The free-host signal fires on legitimate free-hosted sites too, so it only
  adds 8 points and is not counted as a detection above.

Not yet tested: the message rules (urgency wording, generic greeting) against
a labelled set of emails, and the domain age lookup, which needs a live network.

## Round 3 (17 Oct 2026): link structure rules

Five new rules that look at how a link is built and do not depend on the brand
list: a raw IP address as the host, an "@" in the link, punycode (`xn--`)
domains, a chain of five or more subdomain parts, and a brand name in the link
path (a full brand domain such as `/accounts.google.com/`, or a brand word next
to a sign-in word such as `/paypal/auth/login.php`). A message rule was added
too: asking the reader to enter or confirm a password, PIN or card number.

Run `node link-structure-test.mjs`. It uses the 116 full URLs from the 16 Oct
OpenPhish pull (`data/raw-2026-10-16.txt`) and 30 hand-written legitimate links
with paths (`data/legit-urls.json`).

| Result | Value |
|---|---|
| Phishing URLs caught by domain rules alone | 104/116 (89.7%) |
| Caught once the structure rules are added | 107/116 (92.2%) |
| Legitimate links flagged by the structure rules | 2/30 |

What this shows:

- Only the brand-in-path rule fired on real phishing (5 URLs, 3 of them not
  already caught by the domain rules). The IP, "@", punycode and long
  subdomain rules fired on none of the 116 URLs. They are standard phishing
  techniques and cost nothing to include, but this sample gives no evidence
  that they help.
- The 3 extra catches came from the same sample the path rule was designed
  from, so the 92.2% is not a held-out figure.
- The first version of the path rule flagged 4 of the 30 legitimate links
  (article and question titles such as `netflix-password-sharing-update`). It
  now ignores hyphenated slugs longer than three words, which brought that to
  0 of 4 on those links. I wrote the 30 links myself, and I adjusted the rule
  after seeing them, so treat 2/30 as a sanity check and not a measured rate.
- Remaining false positives: a Wikipedia page called `Microsoft_Account`, and
  a made-up five-part CDN hostname.
- A phisher who writes `/paypal-login/` still matches, but one who writes
  `/paypal-account-login-help/` would not.

