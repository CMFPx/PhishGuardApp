// Regression tests for the message-level rules, using the sentences that were
// tried by hand in the app during development. Run: node evaluation/rules-unit-test.mjs
import { analyzeStatic, scoreIndicators, extractDomains, riskLevel } from "../supabase/functions/analyze/rules.ts";

let failed = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : "  " + detail}`);
  if (!ok) failed++;
}
const titles = (t) => analyzeStatic(t).map((i) => i.title);

let t = "Dear Customer, your account will be suspended, please verify immediately at accounts-paypa1.com";
check("greeting + urgency + typosquat all fire", ["Generic greeting", "Urgency language", "Suspicious domain"].every((x) => titles(t).includes(x)), JSON.stringify(titles(t)));

t = "URGENT: verify your identity now at micros0ft-support.com or your account will be suspended";
check("micros0ft-support.com is caught", titles(t).includes("Suspicious domain"), JSON.stringify(titles(t)));

t = "Claim your free reward now at your-prize-today.xyz";
check("urgency + TLD fire on the prize message", titles(t).includes("Urgency language") && titles(t).includes("Suspicious TLD"), JSON.stringify(titles(t)));

t = "Check your account at paypal.com";
check("real paypal.com is not flagged", analyzeStatic(t).length === 0, JSON.stringify(titles(t)));

t = "Sign in at https://accounts.google.com or mail.google.com";
check("subdomains of google.com are not flagged", analyzeStatic(t).length === 0, JSON.stringify(titles(t)));

t = "Your parcel is at amazon.co.nz";
check("amazon.co.nz is not flagged", analyzeStatic(t).length === 0, JSON.stringify(titles(t)));

check("version numbers and file names are not read as domains", extractDomains("Use v1.2 and report.pdf now").join(",") === "report.pdf", extractDomains("Use v1.2 and report.pdf now").join(","));

// ---- link structure and sensitive-request rules (added 17 Oct) ----
t = "Log in here: http://185.220.101.4/secure/login.php";
check("public IP link is flagged", titles(t).includes("Link uses an IP address"), JSON.stringify(titles(t)));

t = "Open http://192.168.1.1/admin to change the router settings";
check("private IP (home router) is not flagged", !titles(t).includes("Link uses an IP address"), JSON.stringify(titles(t)));

t = "Visit https://www.paypal.com@evil-site.net/signin";
check("@ in a link is flagged", titles(t).includes("Link hides its real destination"), JSON.stringify(titles(t)));

t = "Email me at sam@example.com about the invoice";
check("an ordinary email address is not flagged as a hidden link", !titles(t).includes("Link hides its real destination"), JSON.stringify(titles(t)));

t = "Go to https://xn--pypal-4ve.com/login";
check("punycode domain is flagged", titles(t).includes("Look-alike characters in domain"), JSON.stringify(titles(t)));

t = "See https://a.b.c.d.example.org/page";
check("long subdomain chain is flagged", titles(t).includes("Very long subdomain chain"), JSON.stringify(titles(t)));

t = "Sign in: https://mail.intomahost2.com/port/paypal/auth/login.php";
check("brand + sign-in word in the path is flagged", titles(t).includes("Brand name in link path"), JSON.stringify(titles(t)));

t = "Look at https://soydanielc.github.io/accounts.google.com/";
check("brand domain written into the path is flagged", titles(t).includes("Brand name in link path"), JSON.stringify(titles(t)));

t = "Read https://www.example-news.co.nz/business/amazon-opens-new-warehouse";
check("news article that mentions a brand is not flagged", !titles(t).includes("Brand name in link path"), JSON.stringify(titles(t)));

t = "Docs: https://github.com/paypal/paypal-sdk/blob/main/login.md";
check("the brand's own host with a brand path is not flagged", !titles(t).includes("Brand name in link path"), JSON.stringify(titles(t)));

t = "Please enter your password and card number to continue";
check("asking for a password and card number is flagged", titles(t).includes("Asks for sensitive details"), JSON.stringify(titles(t)));

t = "Never share your password with anyone, including us";
check("a warning not to share a password is not flagged", !titles(t).includes("Asks for sensitive details"), JSON.stringify(titles(t)));

const s = scoreIndicators(analyzeStatic("Dear Customer, verify immediately at accounts-paypa1.com"));
check("score is capped at 100 and above 60 for a clear phish", s > 60 && s <= 100, String(s));
check("score for no indicators is the 10 point baseline", scoreIndicators([]) === 10, String(scoreIndicators([])));

check("risk levels match the results panel (60 high, 30 medium)", riskLevel(60) === "high" && riskLevel(59) === "medium" && riskLevel(30) === "medium" && riskLevel(29) === "low" && riskLevel(10) === "low", "");

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
