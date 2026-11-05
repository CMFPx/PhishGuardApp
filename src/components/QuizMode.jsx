import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { supabase } from '../supabaseClient.js'
import MessageCard from '../quiz/MessageCard.jsx'
import {
  CATEGORIES,
  DIFFICULTY_LABEL,
  LENGTHS,
  buildRound,
  chooseQuestionSet,
  loadStats,
  poolSize,
  questionKey,
  resetStats,
  saveStats,
} from '../quiz/quizLogic.js'

// Cuts text at a word boundary and adds an ellipsis, so titles never end mid-word.
function shorten(text, max) {
  const flat = text.replace(/\s+/g, ' ').trim()
  if (flat.length <= max) return flat
  return flat.slice(0, max).replace(/\s+\S*$/, '') + '...'
}

function resultNote(percent) {
  if (percent >= 90) return 'Sharp eyes. Real scams are often harder than these, so keep checking where links go.'
  if (percent >= 70) return 'Solid round. The ones you missed are listed below.'
  if (percent >= 50) return 'A fair start. Read the clues for the ones you missed and try another round.'
  return 'A tricky set. The clues below show what to look at first, and another round will go better.'
}

export default function QuizMode() {
  const [phase, setPhase] = useState('loading')
  const [questions, setQuestions] = useState([])
  const [qSource, setQSource] = useState('bundled')
  const [stats, setStats] = useState(loadStats)

  const [settings, setSettings] = useState({ length: 10, categories: [], difficulty: 'all' })
  const [round, setRound] = useState([])
  const [index, setIndex] = useState(0)
  const [answers, setAnswers] = useState([])
  const [answered, setAnswered] = useState(false)
  const [streak, setStreak] = useState(0)
  const [bestStreakRound, setBestStreakRound] = useState(0)

  const headingRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      // A paused or unreachable database should not leave the page loading,
      // so after 4 seconds the quiz starts with the questions built into the app.
      let rows = null
      try {
        const query = supabase.from('quiz_examples').select('*').order('id')
        const timeout = new Promise((resolve) => setTimeout(() => resolve({ error: true }), 4000))
        const { data, error } = await Promise.race([query, timeout])
        if (!error) rows = data
      } catch {
        rows = null
      }
      if (cancelled) return
      const set = chooseQuestionSet(rows)
      setQuestions(set.questions)
      setQSource(set.source)
      setPhase('setup')
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  const available = useMemo(() => poolSize(questions, settings), [questions, settings])
  const unseenCount = useMemo(() => {
    const seen = new Set(stats.seen)
    return questions.filter(
      (q) =>
        !seen.has(questionKey(q)) &&
        (settings.categories.length === 0 || settings.categories.includes(q.category)) &&
        (settings.difficulty === 'all' || q.difficulty === settings.difficulty),
    ).length
  }, [questions, stats.seen, settings])

  function startRound(customList) {
    const list = customList || buildRound(questions, settings, stats.seen)
    if (list.length === 0) return
    setRound(list)
    setIndex(0)
    setAnswers([])
    setAnswered(false)
    setStreak(0)
    setBestStreakRound(0)
    setPhase('playing')
  }

  const current = round[index]

  const answer = useCallback(
    (guessPhishing) => {
      if (answered || !current) return
      const correct = guessPhishing === current.isPhishing
      const nextStreak = correct ? streak + 1 : 0
      setAnswered(true)
      setStreak(nextStreak)
      setBestStreakRound((b) => Math.max(b, nextStreak))
      setAnswers((a) => [...a, { q: current, guessPhishing, correct }])
      setStats((s) => {
        const seen = s.seen.includes(questionKey(current)) ? s.seen : [...s.seen, questionKey(current)]
        const updated = { ...s, seen, answered: s.answered + 1, correct: s.correct + (correct ? 1 : 0) }
        saveStats(updated)
        return updated
      })
    },
    [answered, current, streak],
  )

  const next = useCallback(() => {
    if (!answered) return
    if (index + 1 >= round.length) {
      const total = round.length
      const right = answers.filter((a) => a.correct).length
      const percent = Math.round((right / total) * 100)
      setStats((s) => {
        const updated = {
          ...s,
          rounds: s.rounds + 1,
          bestPercent: Math.max(s.bestPercent, percent),
          bestStreak: Math.max(s.bestStreak, bestStreakRound),
        }
        saveStats(updated)
        return updated
      })
      setPhase('done')
    } else {
      setIndex((i) => i + 1)
      setAnswered(false)
    }
  }, [answered, answers, bestStreakRound, index, round.length])

  // Keyboard: left arrow = phishing, right arrow = legitimate, Enter = next.
  useEffect(() => {
    if (phase !== 'playing') return undefined
    function onKey(e) {
      if (e.target.closest && e.target.closest('input, textarea')) return
      if (e.key === 'ArrowLeft') answer(true)
      else if (e.key === 'ArrowRight') answer(false)
      else if (e.key === 'Enter' && answered) {
        e.preventDefault()
        next()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [phase, answer, next, answered])

  useEffect(() => {
    if (headingRef.current) headingRef.current.focus({ preventScroll: true })
  }, [index, phase])

  function toggleCategory(c) {
    setSettings((s) => ({
      ...s,
      categories: s.categories.includes(c) ? s.categories.filter((x) => x !== c) : [...s.categories, c],
    }))
  }

  if (phase === 'loading') {
    return <p className="status-line">Loading questions...</p>
  }

  /* ---------- setup ---------- */
  if (phase === 'setup') {
    const accuracy = stats.answered ? Math.round((stats.correct / stats.answered) * 100) : null
    return (
      <section className="quiz-setup" aria-labelledby="quiz-title">
        <div className="setup-intro">
          <h2 id="quiz-title" ref={headingRef} tabIndex={-1}>
            Phish or legitimate?
          </h2>
          <p>
            Each round shows messages in the style of real scams, mixed with genuine ones. Decide which is which, then
            read the clues. About four in ten messages are genuine, so flagging everything will not win.
          </p>
          {stats.answered > 0 && (
            <p className="stats-line">
              You have answered {stats.answered} questions across {stats.rounds}{' '}
              {stats.rounds === 1 ? 'round' : 'rounds'}, {accuracy}% correct. Best round: {stats.bestPercent}%. Longest
              streak: {stats.bestStreak}.{' '}
              <button type="button" className="text-button" onClick={() => setStats(resetStats())}>
                Reset progress
              </button>
            </p>
          )}
        </div>

        <div className="setup-controls">
          <fieldset className="control">
            <legend>Questions in the round</legend>
            <div className="chip-row">
              {LENGTHS.map((n) => (
                <label key={n} className={`chip ${settings.length === n ? 'on' : ''}`}>
                  <input
                    type="radio"
                    name="length"
                    checked={settings.length === n}
                    onChange={() => setSettings((s) => ({ ...s, length: n }))}
                  />
                  {n}
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="control">
            <legend>Difficulty</legend>
            <div className="chip-row">
              {['all', 'easy', 'medium', 'hard'].map((d) => (
                <label key={d} className={`chip ${settings.difficulty === d ? 'on' : ''}`}>
                  <input
                    type="radio"
                    name="difficulty"
                    checked={settings.difficulty === d}
                    onChange={() => setSettings((s) => ({ ...s, difficulty: d }))}
                  />
                  {d === 'all' ? 'Mixed' : DIFFICULTY_LABEL[d]}
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="control">
            <legend>Topics</legend>
            <div className="chip-row">
              {CATEGORIES.map((c) => (
                <label key={c} className={`chip ${settings.categories.includes(c) ? 'on' : ''}`}>
                  <input
                    type="checkbox"
                    checked={settings.categories.includes(c)}
                    onChange={() => toggleCategory(c)}
                  />
                  {c}
                </label>
              ))}
            </div>
            <p className="control-hint">
              {settings.categories.length === 0 ? 'All topics are included.' : `${settings.categories.length} selected.`}
            </p>
          </fieldset>

          <div className="start-row">
            <button type="button" className="primary" onClick={() => startRound()} disabled={available === 0}>
              Start round
            </button>
            <p className="control-hint">
              {available === 0
                ? 'No questions match these choices. Widen the topics or difficulty.'
                : `${available} questions match, ${unseenCount} you have not seen yet.`}
            </p>
          </div>
          {qSource === 'bundled' && (
            <p className="control-hint">Using the question set built into the app.</p>
          )}
        </div>
      </section>
    )
  }

  /* ---------- results ---------- */
  if (phase === 'done') {
    const total = answers.length
    const right = answers.filter((a) => a.correct).length
    const percent = Math.round((right / total) * 100)
    const phishCount = answers.filter((a) => a.q.isPhishing)
    const legitCount = answers.filter((a) => !a.q.isPhishing)
    const missed = answers.filter((a) => !a.correct)

    return (
      <section className="quiz-done" aria-labelledby="done-title">
        <div className="done-score">
          <h2 id="done-title" ref={headingRef} tabIndex={-1}>
            You got {right} of {total}
          </h2>
          <p>{resultNote(percent)}</p>
          <ul className="done-breakdown">
            <li>
              Phishing caught: {phishCount.filter((a) => a.correct).length} of {phishCount.length}
            </li>
            <li>
              Genuine messages trusted: {legitCount.filter((a) => a.correct).length} of {legitCount.length}
            </li>
            <li>Best streak this round: {bestStreakRound}</li>
          </ul>
          <div className="done-actions">
            <button type="button" className="primary" onClick={() => startRound()}>
              Play another round
            </button>
            {missed.length > 0 && (
              <button type="button" className="secondary" onClick={() => startRound(missed.map((a) => a.q))}>
                Retry the {missed.length} I missed
              </button>
            )}
            <button type="button" className="secondary" onClick={() => setPhase('setup')}>
              Change settings
            </button>
          </div>
        </div>

        {missed.length > 0 && (
          <div className="missed">
            <h3>What you missed</h3>
            <ul>
              {missed.map((a) => (
                <li key={questionKey(a.q)}>
                  <p className="missed-title">
                    {a.q.subject || shorten(a.q.body, 60)}
                    <span className={`tag ${a.q.isPhishing ? 'tag-phish' : 'tag-safe'}`}>
                      {a.q.isPhishing ? 'Was phishing' : 'Was genuine'}
                    </span>
                  </p>
                  <p className="missed-from">From {a.q.sender}</p>
                  <p>{a.q.explanation}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    )
  }

  /* ---------- playing ---------- */
  const last = answers[answers.length - 1]
  const wasCorrect = answered && last && last.correct

  return (
    <section className="quiz-play" aria-labelledby="q-title">
      <div className="play-top">
        <ol className="pips" aria-label={`Question ${index + 1} of ${round.length}`}>
          {round.map((_, i) => {
            const a = answers[i]
            const state = a ? (a.correct ? 'right' : 'wrong') : i === index ? 'now' : 'todo'
            return <li key={i} className={`pip ${state}`} />
          })}
        </ol>
        <p className="play-meta">
          Question {index + 1} of {round.length}
          {streak >= 2 && <span className="streak">Streak of {streak}</span>}
        </p>
      </div>

      <h2 id="q-title" className="visually-hidden" ref={headingRef} tabIndex={-1}>
        Question {index + 1}: is this message phishing or legitimate?
      </h2>

      <MessageCard key={questionKey(current)} q={current} revealed={answered} />

      {!answered ? (
        <div className="answer-row">
          <button type="button" className="answer answer-phish" onClick={() => answer(true)}>
            Phishing
          </button>
          <button type="button" className="answer answer-safe" onClick={() => answer(false)}>
            Legitimate
          </button>
          <p className="keys-hint">Keyboard: left arrow for phishing, right arrow for legitimate.</p>
        </div>
      ) : (
        <div className={`feedback ${wasCorrect ? 'feedback-right' : 'feedback-wrong'}`} role="status">
          <p className="feedback-head">
            {wasCorrect ? 'Correct.' : 'Not quite.'} This message is {current.isPhishing ? 'phishing' : 'legitimate'}.
          </p>
          {current.clues.length > 0 && (
            <>
              <p className="feedback-sub">{current.isPhishing ? 'What gave it away' : 'Why it is safe'}</p>
              <ul className="clues">
                {current.clues.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </>
          )}
          <p className="feedback-why">{current.explanation}</p>
          {current.source && (
            <p className="feedback-source">
              {current.sourceUrl ? (
                <a href={current.sourceUrl} target="_blank" rel="noreferrer">
                  {current.source}
                </a>
              ) : (
                current.source
              )}
            </p>
          )}
          <button type="button" className="primary" onClick={next}>
            {index + 1 >= round.length ? 'See results' : 'Next message'}
          </button>
        </div>
      )}
    </section>
  )
}
