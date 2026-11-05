// Pure functions that turn rows from the analysis_log table into dashboard numbers.
// Kept free of React and Supabase so they can be tested against plain arrays.

export const PHISHING_THRESHOLD = 30 // score at or above this counts as "potential phishing"

export function isPhishing(row) {
  return row.score >= PHISHING_THRESHOLD
}

export function filterRows(rows, source) {
  if (source === 'user') return rows.filter((r) => r.source === 'user')
  if (source === 'evaluation') return rows.filter((r) => r.source === 'evaluation')
  return rows
}

export function summarise(rows) {
  const total = rows.length
  const phishing = rows.filter(isPhishing).length
  const sum = rows.reduce((n, r) => n + r.score, 0)
  const levels = { high: 0, medium: 0, low: 0 }
  for (const r of rows) if (levels[r.risk_level] !== undefined) levels[r.risk_level] += 1
  return {
    total,
    phishing,
    phishingPct: total ? (phishing / total) * 100 : 0,
    averageScore: total ? sum / total : 0,
    levels,
  }
}

// Number of checks per calendar day (UTC date string), oldest first, with empty days filled in.
export function dailyCounts(rows) {
  if (!rows.length) return []
  const byDay = new Map()
  for (const r of rows) {
    const day = String(r.created_at).slice(0, 10)
    const e = byDay.get(day) || { day, checks: 0, phishing: 0 }
    e.checks += 1
    if (isPhishing(r)) e.phishing += 1
    byDay.set(day, e)
  }
  const days = [...byDay.keys()].sort()
  const out = []
  const end = new Date(days[days.length - 1] + 'T00:00:00Z')
  for (let d = new Date(days[0] + 'T00:00:00Z'); d <= end; d = new Date(d.getTime() + 86400000)) {
    const key = d.toISOString().slice(0, 10)
    out.push(byDay.get(key) || { day: key, checks: 0, phishing: 0 })
  }
  return out
}

// How often each warning sign fired, most frequent first.
export function topRules(rows, limit = 8) {
  const counts = new Map()
  for (const r of rows) for (const name of r.rules || []) counts.set(name, (counts.get(name) || 0) + 1)
  return [...counts.entries()]
    .map(([rule, count]) => ({ rule, count }))
    .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule))
    .slice(0, limit)
}

// Only meaningful for labelled rows (the evaluation sets).
export function accuracy(rows) {
  const labelled = rows.filter((r) => typeof r.expected_phishing === 'boolean')
  const phish = labelled.filter((r) => r.expected_phishing)
  const legit = labelled.filter((r) => !r.expected_phishing)
  const caught = phish.filter(isPhishing).length
  const falseAlarms = legit.filter(isPhishing).length
  return {
    labelled: labelled.length,
    phishTotal: phish.length,
    caught,
    detectionRate: phish.length ? (caught / phish.length) * 100 : null,
    legitTotal: legit.length,
    falseAlarms,
    falseAlarmRate: legit.length ? (falseAlarms / legit.length) * 100 : null,
  }
}
