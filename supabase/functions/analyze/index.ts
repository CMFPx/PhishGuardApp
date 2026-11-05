import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  analyzeStatic,
  extractDomains,
  isExempt,
  riskLevel,
  scoreIndicators,
  type Indicator,
} from "./rules.ts";

// Lets the function keep working after the response has been sent.
declare const EdgeRuntime: { waitUntil(promise: Promise<unknown>): void } | undefined;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Looks up when a domain was registered (RDAP, the free replacement for WHOIS)
// and flags anything under 90 days old. A 3 second timeout stops a slow
// registry from holding up the answer, and any failure just skips this check.
async function checkDomainAge(domains: string[]): Promise<Indicator | null> {
  for (const domain of domains) {
    if (isExempt(domain)) continue;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);
      const res = await fetch(`https://rdap.org/domain/${domain}`, {
        signal: controller.signal,
        headers: { Accept: "application/rdap+json" },
      });
      clearTimeout(timeout);
      if (!res.ok) continue;

      const data = await res.json();
      const events: { eventAction: string; eventDate: string }[] = data.events ?? [];
      const registration = events.find((e) => e.eventAction === "registration");
      if (!registration) continue;

      const ageDays = (Date.now() - new Date(registration.eventDate).getTime()) / (1000 * 60 * 60 * 24);
      if (ageDays >= 0 && ageDays < 90) {
        return {
          level: "high",
          title: "Recently registered domain",
          desc: `"${domain}" was registered ${Math.floor(ageDays)} day(s) ago. New domains are used in phishing far more than old ones.`,
        };
      }
      return null;
    } catch {
      continue;
    }
  }
  return null;
}

// Records the result of a check for the Analytics page. Only the score, the
// risk level and the names of the rules that fired are saved. The message text
// is never stored. A failure here is logged and ignored so the user still gets
// their result.
async function logResult(score: number, indicators: Indicator[]) {
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !key) return;

    const admin = createClient(url, key, { auth: { persistSession: false } });
    const rules = [...new Set(indicators.filter((i) => i.level !== "neutral").map((i) => i.title))];
    const { error } = await admin
      .from("analysis_log")
      .insert({ score, risk_level: riskLevel(score), rules, source: "user" });
    if (error) console.error("analysis_log insert failed:", error.message);
  } catch (err) {
    console.error("analysis_log insert failed:", String(err));
  }
}

async function analyze(text: string) {
  const indicators = analyzeStatic(text);

  const age = await checkDomainAge(extractDomains(text));
  if (age) indicators.push(age);

  if (indicators.length === 0) {
    indicators.push({
      level: "neutral",
      title: "No indicators found",
      desc: "No urgency wording, generic greeting, brand imitation, risky domain ending, link shortener or new domain was detected.",
    });
  }

  const score = scoreIndicators(indicators);
  const logging = logResult(score, indicators);
  if (typeof EdgeRuntime !== "undefined") EdgeRuntime.waitUntil(logging);
  else await logging;

  return { score, indicators };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { text } = await req.json();

    if (!text || typeof text !== "string") {
      return new Response(
        JSON.stringify({ error: "Missing 'text' in request body" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    return new Response(JSON.stringify(await analyze(text)), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Invalid request", details: String(err) }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  }
});
