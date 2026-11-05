import { useState } from 'react'
import AnalyzeForm from './components/AnalyzeForm.jsx'
import ResultsPanel from './components/ResultsPanel.jsx'
import QuizMode from './components/QuizMode.jsx'
import Analytics from './components/Analytics.jsx'
import Logo from './components/Logo.jsx'
import './App.css'

const HEADLINES = {
  analyze: {
    title: 'Is this message safe to trust?',
    sub: 'Paste an email, a text or a link. PhishGuard scores it and shows exactly what looks wrong.',
  },
  quiz: {
    title: 'Practise spotting scams',
    sub: 'Messages based on real phishing campaigns, mixed with genuine ones, with the clues explained after every answer.',
  },
  analytics: {
    title: 'What PhishGuard is finding',
    sub: 'Totals, trends and the warning signs that fire most often across every check.',
  },
}

export default function App() {
  const [tab, setTab] = useState('analyze')
  const [result, setResult] = useState(null)
  const [status, setStatus] = useState('idle')
  const [error, setError] = useState('')
  const [runId, setRunId] = useState(0)

  const head = HEADLINES[tab]

  return (
    <div className="site">
      <div className="band">
        <div className="shell">
          <header className="site-header">
            <div className="brand">
              <Logo size={40} />
              <span className="wordmark">PhishGuard</span>
            </div>
            <div className="tabs" role="tablist" aria-label="Sections">
              <button
                role="tab"
                id="tab-analyze"
                aria-selected={tab === 'analyze'}
                aria-controls="panel"
                className={`tab ${tab === 'analyze' ? 'active' : ''}`}
                onClick={() => setTab('analyze')}
              >
                Check a message
              </button>
              <button
                role="tab"
                id="tab-quiz"
                aria-selected={tab === 'quiz'}
                aria-controls="panel"
                className={`tab ${tab === 'quiz' ? 'active' : ''}`}
                onClick={() => setTab('quiz')}
              >
                Quiz
              </button>
              <button
                role="tab"
                id="tab-analytics"
                aria-selected={tab === 'analytics'}
                aria-controls="panel"
                className={`tab ${tab === 'analytics' ? 'active' : ''}`}
                onClick={() => setTab('analytics')}
              >
                Analytics
              </button>
            </div>
          </header>

          <div className="hero">
            <h1>{head.title}</h1>
            <p>{head.sub}</p>
          </div>
        </div>
      </div>

      <main className="shell main" id="panel" role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === 'analyze' ? (
          <div className="workspace workspace-split">
            <div className="input-side">
              <AnalyzeForm
                busy={status === 'loading'}
                onStart={() => {
                  setStatus('loading')
                  setError('')
                }}
                onResult={(data) => {
                  setResult(data)
                  setRunId((n) => n + 1)
                  setStatus('done')
                }}
                onError={(msg) => {
                  setResult(null)
                  setError(msg)
                  setStatus('error')
                }}
              />
            </div>
            <ResultsPanel result={result} status={status} error={error} runId={runId} />
          </div>
        ) : tab === 'quiz' ? (
          <div className="workspace">
            <QuizMode />
          </div>
        ) : (
          <div className="workspace">
            <Analytics />
          </div>
        )}
      </main>

      <footer className="shell site-footer">
        <p>
          PhishGuard is a student project for COMP.6208 at Toi Ohomai. It reads the wording and links in a message. It
          cannot confirm that a message is safe.
        </p>
      </footer>
    </div>
  )
}
