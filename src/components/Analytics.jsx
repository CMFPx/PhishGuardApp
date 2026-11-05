import { useEffect, useMemo, useState } from 'react'
import { supabase } from '../supabaseClient.js'
import {
  PHISHING_THRESHOLD,
  filterRows,
  summarise,
  dailyCounts,
  topRules,
  accuracy,
} from '../analytics/analyticsLogic.js'

const PAGE = 1000

// Supabase returns at most 1000 rows per request, so read the table in pages.
async function loadAllRows() {
  const rows = []
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await supabase
      .from('analysis_log')
      .select('created_at, score, risk_level, rules, source, batch, expected_phishing')
      .order('id', { ascending: true })
      .range(from, from + PAGE - 1)
    if (error) throw error
    rows.push(...data)
    if (data.length < PAGE) break
  }
  return rows
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
  ])
}

const SOURCES = [
  { id: 'all', label: 'All checks' },
  { id: 'user', label: 'Live checks' },
  { id: 'evaluation', label: 'Test sets' },
]

const fmt = (n, d = 0) => n.toLocaleString('en-NZ', { maximumFractionDigits: d, minimumFractionDigits: d })

function Stat({ label, value, note, tone }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {note && <div className="stat-note">{note}</div>}
    </div>
  )
}

function TrendChart({ days }) {
  if (days.length === 0) return <p className="muted">No checks yet.</p>
  const W = 640, H = 200, padL = 34, padR = 10, padT = 10, padB = 26
  const max = Math.max(1, ...days.map((d) => d.checks))
  const x = (i) => padL + (days.length === 1 ? (W - padL - padR) / 2 : (i * (W - padL - padR)) / (days.length - 1))
  const y = (v) => padT + (1 - v / max) * (H - padT - padB)
  const line = (key) => days.map((d, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(d[key]).toFixed(1)}`).join(' ')
  const ticks = [0, Math.ceil(max / 2), max]
  const labelIdx = days.length <= 2 ? days.map((_, i) => i) : [0, Math.floor((days.length - 1) / 2), days.length - 1]
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img" aria-label="Checks per day, with potential phishing shown separately">
      {ticks.map((t) => (
        <g key={t}>
          <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} className="grid" />
          <text x={padL - 6} y={y(t) + 4} textAnchor="end" className="axis">{t}</text>
        </g>
      ))}
      <path d={line('checks')} className="line-checks" fill="none" />
      <path d={line('phishing')} className="line-phish" fill="none" />
      {days.length === 1 && (
        <>
          <circle cx={x(0)} cy={y(days[0].checks)} r="4" className="dot-checks" />
          <circle cx={x(0)} cy={y(days[0].phishing)} r="4" className="dot-phish" />
        </>
      )}
      {labelIdx.map((i) => (
        <text key={i} x={x(i)} y={H - 6} textAnchor={i === 0 && days.length > 1 ? 'start' : i === days.length - 1 && days.length > 1 ? 'end' : 'middle'} className="axis">{days[i].day.slice(5)}</text>
      ))}
    </svg>
  )
}

function RuleBars({ rules }) {
  if (rules.length === 0) return <p className="muted">No warning signs recorded yet.</p>
  const max = rules[0].count
  return (
    <ul className="bars">
      {rules.map((r) => (
        <li key={r.rule}>
          <span className="bar-name">{r.rule}</span>
          <span className="bar-track">
            <span className="bar-fill" style={{ width: `${(r.count / max) * 100}%` }} />
          </span>
          <span className="bar-count">{fmt(r.count)}</span>
        </li>
      ))}
    </ul>
  )
}

export default function Analytics() {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState('')
  const [source, setSource] = useState('all')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let live = true
    setRows(null)
    setError('')
    withTimeout(loadAllRows(), 10000)
      .then((r) => live && setRows(r))
      .catch(() =>
        live && setError('The results database did not respond. It may be waking up, so try again in a minute.')
      )
    return () => {
      live = false
    }
  }, [attempt])

  const shown = useMemo(() => (rows ? filterRows(rows, source) : []), [rows, source])
  const sum = useMemo(() => summarise(shown), [shown])
  const days = useMemo(() => dailyCounts(shown), [shown])
  const rules = useMemo(() => topRules(shown), [shown])
  const acc = useMemo(() => accuracy(shown), [shown])

  if (error) {
    return (
      <div className="card analytics-msg">
        <p>{error}</p>
        <button className="primary" onClick={() => setAttempt((n) => n + 1)}>Try again</button>
      </div>
    )
  }
  if (!rows) return <div className="card analytics-msg"><p>Loading results…</p></div>

  return (
    <div className="analytics">
      <div className="analytics-bar">
        <div className="seg" role="group" aria-label="Which checks to include">
          {SOURCES.map((s) => (
            <button key={s.id} className={`seg-btn ${source === s.id ? 'on' : ''}`} aria-pressed={source === s.id} onClick={() => setSource(s.id)}>
              {s.label}
            </button>
          ))}
        </div>
        <p className="muted small">
          Potential phishing means a score of {PHISHING_THRESHOLD} or more. Only scores and warning-sign names are stored, never the message.
        </p>
      </div>

      {sum.total === 0 ? (
        <div className="card analytics-msg">
          <p>No checks recorded for this view yet. Check a message on the first tab and it will show up here.</p>
        </div>
      ) : (
        <>
          <div className="stats">
            <Stat label="Total checks" value={fmt(sum.total)} />
            <Stat label="Potential phishing" value={fmt(sum.phishing)} note={`${fmt(sum.phishingPct, 1)}% of checks`} tone="warn" />
            <Stat label="Average risk score" value={fmt(sum.averageScore, 1)} note="out of 100" />
            <Stat label="High / medium / low" value={`${sum.levels.high} / ${sum.levels.medium} / ${sum.levels.low}`} />
          </div>

          <div className="card">
            <h2>Checks over time</h2>
            <TrendChart days={days} />
            <div className="legend">
              <span><i className="sw sw-checks" /> All checks</span>
              <span><i className="sw sw-phish" /> Potential phishing</span>
            </div>
          </div>

          <div className="card">
            <h2>Most triggered warning signs</h2>
            <RuleBars rules={rules} />
          </div>

          {acc.labelled > 0 && (
            <div className="card">
              <h2>Detection accuracy on labelled test sets</h2>
              <div className="stats">
                <Stat label="Phishing caught" value={`${fmt(acc.detectionRate, 1)}%`} note={`${acc.caught} of ${acc.phishTotal}`} tone="good" />
                <Stat label="Legitimate flagged" value={`${fmt(acc.falseAlarmRate ?? 0, 1)}%`} note={`${acc.falseAlarms} of ${acc.legitTotal}`} tone="warn" />
              </div>
              <p className="muted small">The test sets include a deliberately hard sample, so the catch rate varies a lot between sets.</p>
            </div>
          )}
        </>
      )}
    </div>
  )
}
