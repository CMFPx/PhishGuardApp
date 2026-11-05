import { useEffect, useState } from 'react'

function tierOf(score) {
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

const TIER_COPY = {
  high: {
    title: 'Likely phishing',
    lead: 'Several strong warning signs showed up.',
    next: [
      'Do not click the link or reply.',
      'Open the real website or app yourself by typing its address.',
      'Forward scam texts to 7726 (the Department of Internal Affairs reporting number), and tell the organisation it claims to be from.',
    ],
  },
  medium: {
    title: 'Looks suspicious',
    lead: 'Some warning signs showed up, so check before you act.',
    next: [
      'Do not use the link in the message.',
      'Contact the sender through a phone number or website you already trust.',
      'Be wary if it asks for money, a password or a code.',
    ],
  },
  low: {
    title: 'Few warning signs',
    lead: 'Nothing strong was found, but that does not prove it is safe.',
    next: [
      'PhishGuard only reads the wording and the links.',
      'If the message asks for money, a password or a code, check it another way first.',
    ],
  },
}

const LEVEL_LABEL = { high: 'High risk', medium: 'Worth checking', low: 'Minor', neutral: 'Nothing found' }

// Semicircle gauge. Three coloured bands (low, medium, high) and a needle that sweeps to the score.
function polar(pct, r) {
  const a = Math.PI * (1 - pct / 100)
  return [100 + r * Math.cos(a), 100 - r * Math.sin(a)]
}
function arc(from, to, r = 80) {
  const [x1, y1] = polar(from, r)
  const [x2, y2] = polar(to, r)
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`
}

function Gauge({ score }) {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    const id = requestAnimationFrame(() => setReady(true))
    return () => cancelAnimationFrame(id)
  }, [])
  const deg = -90 + (Math.max(0, Math.min(100, score)) / 100) * 180

  return (
    <svg className="gauge" viewBox="0 0 200 116" role="img" aria-label={`Risk score ${score} out of 100`}>
      <path d={arc(0, 29)} stroke="#2fa877" strokeWidth="16" fill="none" strokeLinecap="round" />
      <path d={arc(32, 59)} stroke="#ffc53d" strokeWidth="16" fill="none" strokeLinecap="round" />
      <path d={arc(62, 100)} stroke="#e8473d" strokeWidth="16" fill="none" strokeLinecap="round" />
      <g
        className="needle"
        style={{ transformOrigin: '100px 100px', transform: `rotate(${ready ? deg : -90}deg)` }}
      >
        <line x1="100" y1="100" x2="100" y2="36" stroke="#2a1740" strokeWidth="4" strokeLinecap="round" />
      </g>
      <circle cx="100" cy="100" r="8" fill="#2a1740" />
    </svg>
  )
}

const CHECKS = [
  'Where the links really go, and how the domain is spelled',
  'Brand names used on websites that do not own them',
  'Look-alike letters, such as a zero in place of an o',
  'Pressure, threats and prizes in the wording',
  'Requests for passwords, codes or card numbers',
  'How recently the website was registered',
]

export default function ResultsPanel({ result, status, error, runId }) {
  if (status === 'loading') {
    return (
      <div className="result-side tier-idle" aria-busy="true">
        <p className="status-line">Checking the message. Looking up the domain can take a few seconds.</p>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="result-side tier-idle">
        <h2 className="result-title">The check did not run</h2>
        <p>PhishGuard could not reach its checker ({error}). Check your internet connection and the Supabase settings in the .env file, then try again.</p>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="result-side tier-idle">
        <h2 className="result-title">What PhishGuard looks at</h2>
        <ul className="check-list">
          {CHECKS.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <p className="result-note">Paste a message on the left to see a score and the reasons behind it.</p>
      </div>
    )
  }

  const tier = tierOf(result.score)
  const copy = TIER_COPY[tier]

  return (
    <div className={`result-side tier-${tier}`} key={runId}>
      <Gauge score={result.score} />
      <p className="score-number">
        {result.score}
        <span> out of 100</span>
      </p>
      <h2 className="result-title" tabIndex={-1}>
        {copy.title}
      </h2>
      <p className="result-lead">{copy.lead}</p>

      <h3 className="result-sub">Why</h3>
      <ul className="indicators">
        {result.indicators.map((ind, i) => (
          <li className={`indicator indicator-${ind.level}`} key={i}>
            <p className="indicator-title">
              {ind.title}
              <span className="indicator-level">{LEVEL_LABEL[ind.level]}</span>
            </p>
            <p className="indicator-desc">{ind.desc}</p>
          </li>
        ))}
      </ul>

      <h3 className="result-sub">What to do</h3>
      <ul className="next-list">
        {copy.next.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </div>
  )
}
