import assert from 'node:assert/strict'
import { summarise, dailyCounts, topRules, accuracy, filterRows } from '../src/analytics/analyticsLogic.js'

const row = (score, day, rules = [], extra = {}) => ({
  score, created_at: `${day}T10:00:00Z`, rules, source: 'user',
  risk_level: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low', ...extra,
})

// no data
assert.deepEqual(summarise([]), { total: 0, phishing: 0, phishingPct: 0, averageScore: 0, levels: { high: 0, medium: 0, low: 0 } })
assert.deepEqual(dailyCounts([]), [])
assert.deepEqual(topRules([]), [])
assert.equal(accuracy([]).detectionRate, null)

// a little data
const few = [row(10, '2026-10-01', ['A']), row(30, '2026-10-01', ['A', 'B']), row(80, '2026-10-03', ['B'])]
const s = summarise(few)
assert.equal(s.total, 3); assert.equal(s.phishing, 2) // 30 counts, 10 does not
assert.equal(s.averageScore, 40)
assert.deepEqual(s.levels, { high: 1, medium: 1, low: 1 })
const d = dailyCounts(few)
assert.equal(d.length, 3) // 1st, 2nd (filled with zero), 3rd
assert.deepEqual(d[1], { day: '2026-10-02', checks: 0, phishing: 0 })
assert.deepEqual(topRules(few), [{ rule: 'A', count: 2 }, { rule: 'B', count: 2 }])

// a lot of data, checked against a direct count
let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648
const many = Array.from({ length: 5000 }, (_, i) => row(Math.floor(rnd() * 101), `2026-09-${String(1 + (i % 28)).padStart(2, '0')}`, i % 3 ? ['X'] : ['X', 'Y']))
const m = summarise(many)
assert.equal(m.total, 5000)
assert.equal(m.phishing, many.filter((r) => r.score >= 30).length)
assert.equal(m.levels.high + m.levels.medium + m.levels.low, 5000)
assert.equal(dailyCounts(many).reduce((n, x) => n + x.checks, 0), 5000)
assert.equal(topRules(many)[0].count, 5000)

// labelled rows and source filter
const lab = [
  row(70, '2026-10-01', [], { source: 'evaluation', expected_phishing: true }),
  row(10, '2026-10-01', [], { source: 'evaluation', expected_phishing: true }),
  row(5, '2026-10-01', [], { source: 'evaluation', expected_phishing: false }),
  row(45, '2026-10-01', [], { source: 'evaluation', expected_phishing: false }),
]
const a = accuracy(lab)
assert.equal(a.detectionRate, 50); assert.equal(a.falseAlarmRate, 50)
assert.equal(filterRows([...few, ...lab], 'evaluation').length, 4)
assert.equal(filterRows([...few, ...lab], 'user').length, 3)
console.log('analytics logic: all tests passed')
