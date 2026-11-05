import bundled from '../data/quizBank.json'

const STORE_KEY = 'phishguard.quiz.v1'

export const CATEGORIES = [...new Set(bundled.map((q) => q.category))].sort()
export const LENGTHS = [5, 10, 20]

// A stable id for a question, so "already seen" survives page reloads.
export function questionKey(q) {
  return `${q.sender}|${q.subject}|${q.body.slice(0, 40)}`
}

// Questions from Supabase use snake_case column names.
export function fromRow(r) {
  return {
    channel: r.channel || 'email',
    sender: r.sender,
    subject: r.subject || '',
    body: r.body,
    linkText: r.link_text || '',
    linkUrl: r.link_url || '',
    isPhishing: r.is_phishing,
    category: r.category || 'General',
    difficulty: r.difficulty || 'medium',
    clues: r.clues || [],
    explanation: r.explanation || '',
    source: r.source || '',
    sourceUrl: r.source_url || '',
  }
}

// Use the database set when it is at least as big as the bundled one.
// If Supabase is paused, empty or out of date, fall back to the bundled set.
export function chooseQuestionSet(rows) {
  // Rows without clues are leftovers from the first version of the table and
  // cannot be explained to the player, so they are skipped.
  const complete = Array.isArray(rows) ? rows.filter((r) => Array.isArray(r.clues) && r.clues.length > 0) : []
  if (complete.length >= bundled.length) {
    return { questions: complete.map(fromRow), source: 'database' }
  }
  return { questions: bundled, source: 'bundled' }
}

function shuffle(list) {
  const a = [...list]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

// Unseen questions come first, each group in random order.
function unseenFirst(list, seen) {
  const fresh = shuffle(list.filter((q) => !seen.has(questionKey(q))))
  const old = shuffle(list.filter((q) => seen.has(questionKey(q))))
  return [...fresh, ...old]
}

// About 40% of a round is legitimate messages, so flagging everything does not win.
export function buildRound(questions, { length, categories, difficulty }, seenKeys) {
  const seen = new Set(seenKeys)
  const pool = questions.filter(
    (q) =>
      (categories.length === 0 || categories.includes(q.category)) &&
      (difficulty === 'all' || q.difficulty === difficulty),
  )
  const phishing = unseenFirst(pool.filter((q) => q.isPhishing), seen)
  const legit = unseenFirst(pool.filter((q) => !q.isPhishing), seen)

  const wantLegit = Math.min(legit.length, Math.round(length * 0.4))
  const wantPhish = Math.min(phishing.length, length - wantLegit)
  let picked = [...phishing.slice(0, wantPhish), ...legit.slice(0, wantLegit)]
  if (picked.length < length) {
    const rest = [...phishing.slice(wantPhish), ...legit.slice(wantLegit)]
    picked = [...picked, ...shuffle(rest).slice(0, length - picked.length)]
  }
  return shuffle(picked)
}

export function poolSize(questions, { categories, difficulty }) {
  return questions.filter(
    (q) =>
      (categories.length === 0 || categories.includes(q.category)) &&
      (difficulty === 'all' || q.difficulty === difficulty),
  ).length
}

const EMPTY = { seen: [], rounds: 0, answered: 0, correct: 0, bestPercent: 0, bestStreak: 0 }

export function loadStats() {
  try {
    const raw = localStorage.getItem(STORE_KEY)
    return raw ? { ...EMPTY, ...JSON.parse(raw) } : { ...EMPTY }
  } catch {
    return { ...EMPTY }
  }
}

export function saveStats(stats) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(stats))
  } catch {
    // Storage can be blocked. The quiz still works without saved progress.
  }
}

export function resetStats() {
  try {
    localStorage.removeItem(STORE_KEY)
  } catch {
    // ignore
  }
  return { ...EMPTY }
}

// "Name <addr@site.com>" -> { name, address }
export function parseSender(sender) {
  const m = sender.match(/^(.*?)\s*<(.+)>$/)
  if (m) return { name: m[1].replace(/^"|"$/g, ''), address: m[2] }
  return { name: '', address: sender }
}

export function splitUrl(url) {
  try {
    const u = new URL(url)
    return { before: `${u.protocol}//`, host: u.host, after: u.pathname + u.search }
  } catch {
    return { before: '', host: url, after: '' }
  }
}

export const CHANNEL_LABEL = { email: 'Email', sms: 'Text message', social: 'Social media message' }
export const DIFFICULTY_LABEL = { easy: 'Easy', medium: 'Medium', hard: 'Hard' }
