# PhishGuard (scaffold)

A React scaffold for the PhishGuard project, connected to a real Supabase
project with a working Edge Function. Both tabs now call real backend
infrastructure instead of using hardcoded/fake logic in the browser:

- **Analyse tab** → calls the `analyze` Edge Function deployed to Supabase.
  It currently runs the same placeholder rules the old `fakeAnalyze()` used
  to run locally in the browser — the point of this step was proving the
  React → Edge Function → response round trip works before writing real
  detection logic.
- **Quiz mode tab** → fetches its questions from the `quiz_examples` table
  in Supabase.


## Running locally in VS Code

1. Unzip this folder and open it in VS Code.
2. Open a terminal in VS Code (`` Ctrl+` `` / `` Cmd+` ``).
3. Install dependencies:
   ```
   npm install
   ```
4. A `.env` file is already included with your project's URL and anon key,
   so it should work out of the box. If you ever need to reconnect it to a
   different Supabase project, copy `.env.example` to `.env` and fill in
   your own values from the Supabase dashboard (Project Settings → API).
5. Start the dev server:
   ```
   npm run dev
   ```
6. Open the URL it prints (usually `http://localhost:5173`) in your browser.

## What's here

```
src/
  App.jsx                    Tab switching between Analyse and Quiz mode
  App.css                    All styling
  supabaseClient.js          Supabase client setup (reads from .env)
  components/
    AnalyzeForm.jsx           Input box + fake detection logic (still a placeholder)
    ResultsPanel.jsx           Risk score + indicator cards
    QuizMode.jsx                Training/quiz mode — now loads questions from Supabase
```

## Supabase setup

Project: `phishguard` (region: ap-southeast-2)

Table `quiz_examples`:
| column | type | notes |
|---|---|---|
| id | bigint | auto-generated |
| sender | text | the "From" address shown in the quiz |
| body | text | the message body |
| is_phishing | boolean | correct answer |
| explanation | text | shown after answering |
| created_at | timestamptz | auto-set |

Row Level Security is enabled with a public read policy (`select` only) —
fine for now since it's just training content, no sensitive data. If you
later add a way for users to submit their own examples, you'll want to
lock down `insert`/`update` properly.

## Edge Functions

Function `analyze` (deployed as version 10, JWT verification on — the Supabase client
automatically sends your anon key, so no extra setup needed). Source is also
saved locally in `supabase/functions/analyze/` (`index.ts` handles the request and the domain age lookup, `rules.ts` holds all the detection rules and is also what the evaluation scripts import) for version control —
edit it there and redeploy via the Supabase CLI or dashboard to keep both in
sync.

Current detection logic — all six rules from the proposal's scope are now
implemented, plus one added after testing revealed a gap:
- **Urgency language** — broadened regex covering pressure phrasing, threat
  framing ("account suspended", "unauthorized activity"), false reward
  framing ("you've won", "claim now"), and time pressure ("expires soon",
  "final notice").
- **Generic greeting** — regex for "Dear Customer"/"Dear User". Still a
  simple placeholder rule — fine for now, could be broadened later.
- **Typosquatting/domain similarity** — extracts domains from the submitted
  text and compares each against a list of known legitimate domains using
  Levenshtein edit distance, both as a whole domain and token-by-token.
  Catches near-misses (e.g. `paypa1.com`, `micros0ft-support.com`).
- **Brand impersonation** *(added after testing)* — catches a known brand
  name used verbatim inside an unrelated domain (e.g.
  `coinbaseverify.vercel.app`, `wellsfargogethelp.com`). Different from
  typosquatting: the brand name is exact, not misspelled, just glued onto
  unrelated free-hosting infrastructure. Testing showed this is actually
  the dominant real-world pattern.
- **Suspicious TLD** — flags domains ending in TLDs disproportionately
  associated with phishing/spam (`.xyz`, `.top`, `.tk`, etc).
- **URL shortener** — flags known link-shortening domains (bit.ly, tinyurl,
  etc) that could be masking the real destination.
- **Link structure** *(added 17 Oct)* — flags links that use a raw IP address,
  contain an "@", use an `xn--` domain or a long subdomain chain, or put a brand
  name in the path of an unrelated site (e.g. `/paypal/auth/login.php`).
- **Sensitive request** *(added 17 Oct)* — flags wording that asks the reader to
  enter or confirm a password, PIN or card number.
- **Recently registered domain (WHOIS/RDAP)** — calls the RDAP protocol
  (the modern, free, no-API-key replacement for WHOIS) to check a domain's
  registration date, flagging anything registered in the last 90 days. Has
  a 3-second timeout and fails silently (skips the check) if the lookup
  errors, so a slow/unreachable registry never breaks the whole analysis.

## Evaluation

The domain rules (typosquatting, brand impersonation, suspicious TLD, URL
shortener, free-host signal) are tested against live phishing feeds and a
labelled set of legitimate domains. See `evaluation/README.md` for the method
and full tables. Short version:

- 24 Sep OpenPhish sample (52 domains): 75.0% caught, up from 3.8% before the
  brand list was expanded.
- 16 Oct OpenPhish sample (116 domains): 79.3% for the rules deployed on 24 Sep,
  89.7% for the current rules (tuned on this sample, so it overstates).
- 16 Oct PhishTank sample (23 domains, held out): 43.5%. Missing brands and
  sites with no brand in the hostname are the main misses.
- Legitimate domains flagged by the current rules: 0 of 44 primary brand
  domains, 0 of 27 related domains, 0 of 4 free-hosted sites, 3 of 3 unrelated
  domains that happen to contain a brand word.

With the link structure rules, 107 of the 116 URLs in the 16 Oct sample are
caught (92.2%), and 2 of 30 hand-written legitimate links are flagged (see
Round 3 in `evaluation/README.md`).

Run the comparison with `node evaluation/domain-rules-test-v2.mjs` and the
regression tests with `node evaluation/rules-unit-test.mjs` (Node 22.18+).
Results are also logged in the `evaluation_results` table in Supabase.

## Quiz questions

The quiz has 57 messages (37 phishing, 20 genuine) across eight topics and three
difficulty levels, covering email, text and social media messages. They are
written for the quiz, in the style of scams that Inland Revenue, Netsafe, ANZ,
Westpac and NZ Post have warned about, plus common patterns from a published
catalogue of phishing emails. Each question lists its source and says plainly
when the wording was written for this quiz. All domains and numbers in the
questions are made up.

The questions live in two places:

- `src/data/quizBank.json` is built into the app, so the quiz works even if
  Supabase is paused. If the database does not answer within 4 seconds, the quiz
  starts with this set.
- The `quiz_examples` table in Supabase holds the same questions. To load them,
  paste `supabase/seed/quiz_examples.sql` into the Supabase SQL editor and run
  it. The app uses the database set once it has at least 57 complete questions
  (rows with no clues are ignored), and it says "Using the question set built
  into the app" on the setup screen when it falls back.

## Known Supabase free-tier gotcha

Free-tier Supabase projects auto-pause after a period of inactivity (data
in the database can be lost on a long pause — this happened once already
during development, the table had to be recreated). If the app suddenly
can't reach Supabase after a break, check the project status in the
Supabase dashboard and restore it if it shows as paused/inactive.


**Known limitations** (for the critical evaluation): the rules only read
the domain, so phishing with no brand in the hostname is not caught, and the
brand list sets the ceiling on what is detected. Matching a brand word inside
a longer name also flags innocent domains (all 3 test cases of that kind were
flagged), which is why that rule only scores medium. The free-host signal
fires on legitimate sites too and adds only a few points.

## Next steps (not done yet, on purpose)

- Domain-based rules have real, evaluated results (see above). Urgency
  language and generic greeting rules haven't been tested against a labelled
  message dataset yet — only against a handful of manual examples so far.
- The misses (brands not on the list, and sites with no brand in the
  domain) are a documented limitation of domain-only rules. The final report
  should state the measured false positive groups, not only the headline rate.
- Add a table to log analysed submissions and scores from real usage (not
  just the evaluation script), for further evidence in the report.

## Analytics tab

The Analytics tab reads the `analysis_log` table (scores, risk levels and warning-sign names only, never message text) and shows total checks, potential phishing (score of 30 or more), average score, a checks-over-time chart, the most triggered warning signs and, for labelled test sets, detection accuracy. The calculations live in `src/analytics/analyticsLogic.js` and are tested by `node evaluation/analytics-logic-test.mjs` (no data, a little data, 5000 rows checked against direct counts).

Setup order: apply `supabase/migrations/20261029_create_analysis_log.sql`, deploy the `analyze` function, then run `supabase/seed/analysis_log_evaluation.sql`.
